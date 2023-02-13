#include <iostream>
#include <Windows.h>

using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

int main()
{
	std::cout << "Loading dll" << std::endl;
	system("pause");
	LoadLibraryA("Dll.dll");
	std::cout << "Dll loaded, calling shit" << std::endl;

	

	unsigned char buf[4];
	DWORD sizeRead = 0;
	BOOL readReturn = ReadProcessMemory(GetCurrentProcess(), (void*)0x7ffe0000, buf, sizeof(buf), &sizeRead);
	if (readReturn)
	{
		std::cout << "Read proc memory succeeded. Bytes: " << std::hex << (int)buf[0] << (int)buf[1] << (int)buf[2] << (int)buf[3] << std::endl;
	}
	else
	{
		std::cout << "Failed to read process memory: " << GetLastError() << std::endl;
	}

	NtReadVirtualMemory_t NtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory");
	DWORD sizeRead2 = sizeof(buf);
	NTSTATUS status = NtReadVirtualMemory((HANDLE)-1, (void*)0x7ffe0000, buf, sizeof(buf), &sizeRead2);
	if (status >= 0)
	{
		std::cout << "NtRead proc memory succeeded. Bytes: " << std::hex << (int)buf[0] << (int)buf[1] << (int)buf[2] << (int)buf[3] << std::endl;
	}
	else
	{
		std::cout << "Failed to NtRead process memory: " << status << std::endl;
	}

	system("pause");

}