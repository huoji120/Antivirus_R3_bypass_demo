#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <psapi.h>
#include <ctype.h>

#include "gpuz.h"
#include "sys.h"
#include "Utils.h"



#pragma comment(lib, "ntdll.lib")
#pragma warning(disable : 4996)



typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;