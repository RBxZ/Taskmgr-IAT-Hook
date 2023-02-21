# Taskmgr-IAT-Hook
C program that IAT hooks the "Taskmgr.exe" process and makes it miss running processes

How does it work?

The evil file is a DLL, that its main function preforms the hook itself. 
It runs on the process PE format and finds its IAT. 
It then finds the address of the NtQuerySystemInformation() function (The function that Taskmgr uses to get the information about all the processes), and replaces it with a pointer to my function.
My function does the exact same thing, only it ignores a process that I choose, causing it to not apear in the taskmgr window.
The injector file loads the DLL to the taskmgr process and lets it do its magic.
