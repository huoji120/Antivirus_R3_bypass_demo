#pragma once
class gpuz
{
public:
	gpuz();
	~gpuz();

	BOOLEAN ReadSystemAddress(PVOID Address, PVOID Buffer, SIZE_T Length);
	template <typename T, typename U>
	T ReadSystemAddress(U Address)
	{
		T Buff{ 0 };
		if (!ReadSystemAddress((PVOID)Address, &Buff, sizeof(T)))
		{
			return Buff;
		}
		return Buff;
	}

	BOOLEAN WriteSystemAddress(PVOID Address, PVOID Buffer, SIZE_T Length);
	template <typename T, typename U>
	BOOLEAN WriteSystemAddress(U Address, T Value)
	{
		return WriteSystemAddress((PVOID)Address, &Value, sizeof(T));
	}
	uint64_t TranslateVirtualAddress(uint64_t directoryTableBase, PVOID virtualAddress);
	BOOLEAN ReadPhysicalAddress(uint64_t Address, PVOID Buffer, SIZE_T Length);
	template <typename T, typename U>
	T ReadPhysicalAddress(U Address)
	{
		T Buff{ 0 };
		if (!ReadPhysicalAddress((uint64_t)Address, &Buff, sizeof(T)))
		{
			return Buff;
		}
		return Buff;
	}
	BOOLEAN WritePhysicalAddress(uint64_t Address, PVOID Buffer, SIZE_T Length);
private:
	BOOLEAN ReadCR3();

	HANDLE hDevice = INVALID_HANDLE_VALUE;
	uint64_t ControlReg3 = 0;


	

};

