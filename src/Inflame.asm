format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 3
    jne error
    stdcall injectLoadLibraryA
    invoke ExitProcess, 0

error:
    cinvoke printf, <'Wrong amount of Command line arguments! Press enter to continue...', 0>
    cinvoke getchar
    invoke ExitProcess, 1

proc injectLoadLibraryA
    locals
        dllPath rb MAX_PATH
        dllPathLength dd ?
        processHandle dd ?
        allocatedMemory dd ?
    endl

    mov esi, [argv]
    lea eax, [dllPath]
    invoke GetFullPathNameA, dword [esi + 4], MAX_PATH, eax, 0
    lea eax, [dllPath]
    cinvoke strlen, eax
    inc eax
    mov [dllPathLength], eax
    mov esi, [argv]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, <cinvoke atoi, dword [esi + 8]>
    mov [processHandle], eax
    lea eax, [dllPathLength]
    lea ebx, [processHandle]
    invoke VirtualAllocEx, dword [ebx], NULL, eax, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], eax
    lea eax, [dllPath]
    lea ebx, [dllPathLength]
    lea ecx, [processHandle]
    lea edx, [allocatedMemory]
    invoke WriteProcessMemory, dword [ecx], dword [edx], eax, dword [ebx], NULL
    lea ebx, [processHandle]
    lea esi, [allocatedMemory]
    invoke CreateRemoteThread, dword [ebx], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, dword [esi], 0, NULL
    lea eax, [processHandle]
    invoke CloseHandle, dword [eax]
    ret
endp

proc injectManualMap
    locals
        dllHandle dd ?
        dllSize dd ?
    endl

    mov esi, [argv]
    invoke CreateFileA, dword [esi + 4], GENERIC_READ, FILE_SHARE_READ + FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    mov [dllHandle], eax
    ret
endp

section '.bss' data readable writable

argc    dd ?
argv    dd ?
env     dd ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'

import kernel32, \
       ExitProcess, 'ExitProcess', \
       GetFullPathNameA, 'GetFullPathNameA', \
       GetModuleHandleA, 'GetModuleHandleA', \
       GetProcAddress, 'GetProcAddress', \
       OpenProcess, 'OpenProcess', \
       VirtualAllocEx, 'VirtualAllocEx', \
       WriteProcessMemory, 'WriteProcessMemory', \
       CreateRemoteThread, 'CreateRemoteThread', \
       CloseHandle, 'CloseHandle', \
       CreateFileA, 'CreateFileA', \
       GetFileSize, 'GetFileSize'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar', \
       strlen, 'strlen', \
       atoi, 'atoi'
