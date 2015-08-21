#include <cstdio>
#include <vector>
#include <Windows.h>

#include "undocumented.h"

using pNtQueryInformationProcess = NTSTATUS(NTAPI *)(HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS_FULL ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength, PULONG ReturnLength);
pNtQueryInformationProcess NtQueryInformationProcess = nullptr;

void EnumerateProcessDlls(const HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION procBasicInfo = { 0 };
	ULONG ulRetLength = 0;
	NTSTATUS ntStatus = NtQueryInformationProcess(hProcess,
		PROCESS_INFORMATION_CLASS_FULL::ProcessBasicInformation, &procBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION), &ulRetLength);
	if (ntStatus != STATUS_SUCCESS)
	{
		fprintf(stderr, "Could not get process information. Status = %X\n",
			ntStatus);
		exit(-1);
	}

	PEB procPeb = { 0 };
	SIZE_T ulBytesRead = 0;
	bool bRet = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)procBasicInfo.PebBaseAddress, &procPeb,
		sizeof(PEB), &ulBytesRead));
	if (!bRet)
	{
		fprintf(stderr, "Failed to read PEB from process. Error = %X\n",
			GetLastError());
		exit(-1);
	}

	PEB_LDR_DATA pebLdrData = { 0 };
	bRet = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)procPeb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA),
		&ulBytesRead));
	if (!bRet)
	{
		fprintf(stderr, "Failed to read module list from process. Error = %X\n",
			GetLastError());
		exit(-1);
	}

	LIST_ENTRY *pLdrListHead = (LIST_ENTRY *)pebLdrData.InLoadOrderModuleList.Flink;
	LIST_ENTRY *pLdrCurrentNode = pebLdrData.InLoadOrderModuleList.Flink;
	do
	{
		LDR_DATA_TABLE_ENTRY lstEntry = { 0 };
		bRet = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)pLdrCurrentNode, &lstEntry,
			sizeof(LDR_DATA_TABLE_ENTRY), &ulBytesRead));
		if (!bRet)
		{
			fprintf(stderr, "Could not read list entry from LDR list. Error = %X\n",
				GetLastError());
			exit(-1);
		}

		pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

		WCHAR strFullDllName[MAX_PATH] = { 0 };
		WCHAR strBaseDllName[MAX_PATH] = { 0 };
		if (lstEntry.FullDllName.Length > 0)
		{
			bRet = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)lstEntry.FullDllName.Buffer, &strFullDllName,
				lstEntry.FullDllName.Length, &ulBytesRead));
			if (bRet)
			{
				wprintf(L"Full Dll Name: %s\n", strFullDllName);
			}
		}

		if (lstEntry.BaseDllName.Length > 0)
		{
			bRet = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)lstEntry.BaseDllName.Buffer, &strBaseDllName,
				lstEntry.BaseDllName.Length, &ulBytesRead));
			if (bRet)
			{
				wprintf(L"Base Dll Name: %s\n", strBaseDllName);
			}
		}

		if (lstEntry.DllBase != nullptr && lstEntry.SizeOfImage != 0)
		{
			wprintf(
				L"  Dll Base: %p\n"
				L"  Entry point: %p\n"
				L"  Size of Image: %X\n",
				lstEntry.DllBase, lstEntry.EntryPoint, lstEntry.SizeOfImage);
		}

	} while (pLdrListHead != pLdrCurrentNode);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <process id>\n",
			argv[0]);
		exit(-1);
	}

	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	NtQueryInformationProcess =
		(pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == nullptr)
	{
		fprintf(stderr, "Could not retrieve NtQueryInformationProcess. Error = %X\n",
			GetLastError());
		exit(-1);
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, atoi(argv[1]));
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Could not open handle to process. Error = %X\n",
			GetLastError());
		exit(-1);
	}

	EnumerateProcessDlls(hProcess);

	CloseHandle(hProcess);

	return 0;
}