#pragma once
class sys
{
public:
	sys(uint32_t BuildNumber);
	~sys();

	uint64_t QueryVar();
	BOOLEAN DisableDSE();
	BOOLEAN EnableDSE();
	gpuz* Driver = nullptr;

private:
	PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass);
	BOOLEAN GetSystemImageInformation(const char* SystemModuleName, uint64_t* ImageBase);
	uint64_t g_CiVar = 0;

	uint32_t dwBuildNumber = -1;
	char szSystemPath[MAX_PATH];
	MODULEINFO ModInfo{ 0 };

	const char* ImageName = nullptr;
	const char* VariablePattern = nullptr;
	int AddressOffset = 0;
};

