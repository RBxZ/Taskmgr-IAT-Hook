#include <Windows.h>
#include <stdio.h>


int main() {
	DWORD pid = 0;
	scanf("%d", &pid);
	char* buffer = "E:/Sahar/Task Maneger/evill/Debug/evill.dll";
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (handle == NULL)
	{
		printf("Did not find process");
		return -1;
	}
	LPVOID memmory = VirtualAllocEx(handle, NULL, strlen(buffer) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (memmory == NULL) {
		printf("Problem in memmory");
		return -1;
	}
	int n = WriteProcessMemory(handle, memmory, buffer, strlen(buffer) + 1, NULL);
	if (n == 0) {
		printf("Could not write to memmory");
		return -1;
	}
	HANDLE thread = CreateRemoteThread(handle, NULL, 0, &LoadLibraryA, memmory, NULL, NULL);
	if (thread == NULL) {
		printf("Did not create thread");
		return -1;
	}
}
