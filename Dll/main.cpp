#include <iostream>
#include <Windows.h>
#include "stackframe.h"

#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using Callback_t = void(*)();
struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG version;
	ULONG reserved;
	Callback_t callback;
};
using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE processHandle, PROCESS_INFORMATION_CLASS processInformationClass, PVOID processInformation, ULONG processInformationLength);

extern "C" void InstrumentationCallbackProxy(VOID);
extern "C" void InstrumentationCallback(uintptr_t, uintptr_t, uintptr_t);

NtSetInformationProcess_t NtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSetInformationProcess");
unsigned int ntReadVirtualMemoryIndex = -1;


unsigned int ExtractSyscallIndexForNtdllFunc(const char* functionName)
{
	unsigned char* functionAddress = reinterpret_cast<unsigned char*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), functionName));
	if (!functionAddress || functionAddress[0] != 0xB8 || functionAddress[5] != 0xBA)
		return -1;

	return *reinterpret_cast<unsigned int*>(functionAddress + 1);
}

void InstrumentationCallback(uintptr_t returnAddress, uintptr_t returnVal, uintptr_t previousSpMinus4)
{
	uintptr_t teb = (uintptr_t)NtCurrentTeb();
	constexpr int cbDisableOffset = 0x01B8;   // TEB32->InstrumentationCallbackDisabled offset
	uintptr_t* instrumentationCallbackDisabled = reinterpret_cast<uintptr_t*>(teb + cbDisableOffset);

	if (!(*instrumentationCallbackDisabled))
	{
		*instrumentationCallbackDisabled = 1; // TEB->InstrumentaionCallbackDisabled flag to prevent recursion.

		unsigned char* opCodes = reinterpret_cast<unsigned char*>(returnAddress - 0xC); // returnAddress is at ret instruction, so we move back to the mov eax instruction
		if (opCodes && opCodes[0] == 0xB8 && opCodes[5] == 0xBA) // Windows 10 only
		{
			const unsigned int syscallNumber = *reinterpret_cast<unsigned int*>(opCodes + 1);
			if (syscallNumber == ntReadVirtualMemoryIndex)
			{
				const auto arguments = reinterpret_cast<void**>(previousSpMinus4 + 8); // + 4 to get to stack ptr, + 4 to get to arguments

				const auto processHandle = reinterpret_cast<HANDLE>(arguments[0]);
				const auto address = reinterpret_cast<uintptr_t>(arguments[1]);
				const auto buffer = reinterpret_cast<unsigned char*>(arguments[2]);
				const auto bufferSize = reinterpret_cast<size_t>(arguments[3]);
				const auto sizeRead = reinterpret_cast<size_t*>(arguments[4]);

				buffer[0] = 0x88;
				buffer[1] = 0x69;
				


				STACKFRAME();
				const auto caller = STACK_FRAME.PreviousFrame().GetReturnAddress().GetPtr();

				std::cout << "Readprocessmemory hook!! coming from: 0x" << std::hex << caller << std::endl;
			}
		}

		*instrumentationCallbackDisabled = 0;
	}
}

void SetupHook()
{
	ntReadVirtualMemoryIndex = ExtractSyscallIndexForNtdllFunc("NtReadVirtualMemory");
	if (ntReadVirtualMemoryIndex == -1)
	{
		std::cout << "Syscall index for NtReadVirtualMemory not found :(" << std::endl;
		return;
	}

	std::cout << "Syscall index for NtReadVirtualMemory: 0x" << std::hex << ntReadVirtualMemoryIndex << std::endl;

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callbackInfo;
	callbackInfo.version = (ULONG)InstrumentationCallbackProxy;
	callbackInfo.callback = InstrumentationCallbackProxy;
	callbackInfo.reserved = 0;

	NTSTATUS status = NtSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &callbackInfo, sizeof(callbackInfo));
	if (!NT_SUCCESS(status))
		std::cout << "Failed to install hook: 0x" << std::hex << status << std::endl;
	else
		std::cout << "Installed hook successfully..." << std::endl;
}

void RemoveHook()
{

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReasonForCall, LPVOID lpReserved)
{
	switch (ulReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
	{
		std::cout << "helllo wooorld" << std::endl;
		SetupHook();
		return TRUE;
	}
	case DLL_PROCESS_DETACH:
	{
		return TRUE;
	}
	default:
		break;
	}
	return TRUE;
}