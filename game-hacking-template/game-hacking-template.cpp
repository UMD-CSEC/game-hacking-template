// simple-example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <array>
#include <span>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define TARGET_PROCESS L"ac_client.exe"
#define PTR_OFFSET(ptr, off) ((LPVOID)((INT_PTR)(ptr) + (off)))

HANDLE g_process;
LPVOID g_image_base;

__declspec(noreturn) static void die(const char *msg) {
	LPTSTR error_msg;
	DWORD error = GetLastError();
	DWORD res = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		LANG_USER_DEFAULT,
		(LPTSTR)&error_msg,
		0, NULL);
	if (res == 0) {
		std::cerr << "Failed to print error message: " << msg << std::endl;
		goto out;
	}

	std::wcerr << msg << ": " << error_msg << std::endl;
	LocalFree(error_msg);
out:
	ExitProcess(error);
}

HANDLE get_target_process() {
	PROCESSENTRY32 process;
	DWORD pid;
	HANDLE process_handle;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		die("CreateToolhelp32Snapshot");

	process.dwSize = sizeof(process);
	if (!Process32First(snapshot, &process))
		die("Process32First");

	pid = 0;
	do {
		if (lstrcmpW(process.szExeFile, TARGET_PROCESS) == 0) {
			pid = process.th32ProcessID;
			break;
		}
	} while (Process32Next(snapshot, &process));

	if (pid == 0)
		return NULL;
	
	// pid found - now we just need to open process
	process_handle = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid);

	return process_handle;
}

static void dump_mappings(HANDLE process) {
	INT_PTR curr_addr = 0;
	MEMORY_BASIC_INFORMATION mem_info;

	while (VirtualQueryEx(process, (LPCVOID) curr_addr, &mem_info, sizeof(mem_info)) != 0) {
		std::cout << "[" << mem_info.BaseAddress << " - " << (LPVOID)((INT_PTR) mem_info.BaseAddress + mem_info.RegionSize) << + "]: ";
		const char* perm_str = "???";
		switch (mem_info.Protect) {
		case PAGE_EXECUTE:
			perm_str = "--X";
			break;
		case PAGE_EXECUTE_READ:
			perm_str = "R-X";
			break;
		case PAGE_EXECUTE_READWRITE:
			perm_str = "RWX";
			break;
		case PAGE_EXECUTE_WRITECOPY:
			perm_str = "RCX";
			break;
		case PAGE_NOACCESS:
			perm_str = "---";
			break;
		case PAGE_READONLY:
			perm_str = "R--";
			break;
		case PAGE_READWRITE:
			perm_str = "RW-";
			break;
		case PAGE_WRITECOPY:
			perm_str = "RC-";
			break;
		}
		std::cout << perm_str << " | ";

		switch (mem_info.Type) {
		case MEM_IMAGE:
			std::cout << "MEM_IMAGE   ";
			break;
		case MEM_MAPPED:
			std::cout << "MEM_MAPPED  ";
			break;
		case MEM_PRIVATE:
			std::cout << "MEM_PRIVATE ";
			break;
		default:
			std::cout << "UNKNOWN     ";
			break;
		}

		// get name of file if it exists
		CHAR path[MAX_PATH] = { 0 };
		GetMappedFileNameA(process, mem_info.BaseAddress, path, sizeof(path)-1);
		LPCSTR filename = PathFindFileNameA(path);

		std::cout << "(" << filename << ")" << std::endl;

		curr_addr = (INT_PTR)mem_info.BaseAddress + mem_info.RegionSize;
	}
}

// gets the base address of TARGET_PROCESS
static LPVOID get_image_base(HANDLE process) {
	INT_PTR curr_addr = 0;
	MEMORY_BASIC_INFORMATION mem_info;

	while (VirtualQueryEx(process, (LPCVOID)curr_addr, &mem_info, sizeof(mem_info)) != 0) {
		// get name of file if it exists
		TCHAR path[MAX_PATH+1] = { 0 };
		GetMappedFileName(process, mem_info.BaseAddress, path, MAX_PATH);
		LPTSTR filename = PathFindFileNameW(path);

		if (lstrcmp(filename, TARGET_PROCESS) == 0) {
			return (LPVOID) mem_info.BaseAddress;
		}

		curr_addr = (INT_PTR)mem_info.BaseAddress + mem_info.RegionSize;
	}

	return 0;
}

// same argument order as memcpy
// i hate windows
static void mem_read(LPVOID dst, LPCVOID src, SIZE_T n) {
	if (ReadProcessMemory(g_process, src, dst, n, NULL) == 0) {
		die("ReadProcessMemory");
	}
}
static void mem_write(LPVOID dst, LPCVOID src, SIZE_T n) {
	if (WriteProcessMemory(g_process, dst, src, n, NULL) == 0) {
		die("WriteProcessMemory");
	}
}

// returns the address obtained after resolving the pointer chain
// if you are unfamiliar with std::span, you can think of it as an array
static LPVOID mem_resolve_ptr_chain(LPCVOID start, std::span<const DWORD> chain) {
	DWORD curr_ptr = (DWORD) start;
	for (DWORD offset : chain) {
		mem_read(&curr_ptr, (LPCVOID)curr_ptr, sizeof(DWORD));
		curr_ptr = curr_ptr + offset;
	}

	return (LPVOID) curr_ptr;
}

int main()
{
	g_process = get_target_process();
	if (g_process == NULL) {
		die("failed to open target process");
	}

	std::wcout << "Opened " << TARGET_PROCESS << " handle: " << g_process << std::endl;

	// find memory of process
	//dump_mappings(g_process);
	g_image_base = get_image_base(g_process);
	if (g_image_base == 0) {
		die("failed to find target image base");
	}
	std::cout << "Found image base: " << g_image_base << std::endl;

	if (CloseHandle(g_process) == 0) {
		die("CloseHandle");
	}
	return 0;
}