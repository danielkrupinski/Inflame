format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 4
    jne error
    mov esi, [argv]
    cinvoke atoi, dword [esi + 4]
    cmp eax, 1
    je loadlibrary
    cmp eax, 2
    je manualmap
    invoke ExitProcess, 0

loadlibrary:
    stdcall injectLoadLibraryA

manualmap:
    stdcall injectManualMap

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
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, eax, 0
    lea eax, [dllPath]
    cinvoke strlen, eax
    inc eax
    mov [dllPathLength], eax
    mov esi, [argv]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, <cinvoke atoi, dword [esi + 12]>
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
    mov esi, [argv]
    cinvoke atoi, dword [esi + 12]
    mov esi, [argv]
    cinvoke manualMap, dword [esi + 8], eax
    ret
endp

section '.bss' data readable writable

argc    dd ?
argv    dd ?
env     dd ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll', \
        Inflame, 'Inflame.dll'

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
       GetFileSize, 'GetFileSize', \
       VirtualAlloc, 'VirtualAlloc', \
       ReadFile, 'ReadFile'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar', \
       strlen, 'strlen', \
       atoi, 'atoi', \
       strcmp, 'strcmp'

import Inflame, \
       manualMap, 'manualMap'
