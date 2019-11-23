#pragma once
class Utils
{
public:
	uint64_t FindPattern(uint64_t start, uint64_t size, const char* pattern, DWORD address_offset);
	char* ToLower(char* szText);
	static Utils& instance();
	BOOLEAN EnablePrivilege(const char* lpPrivilegeName);
	BOOLEAN RegisterService(std::string ServicePath, std::string *ServiceRegKey);
	NTSTATUS LoadDriver(std::string ServiceRegKey);
	NTSTATUS UnloadDriver(std::string ServiceRegKey);

private:
	BOOLEAN InitNativeFuncs();

	BOOLEAN m_bIsNativeInitialized = FALSE;
};

