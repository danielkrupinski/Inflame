format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 4
    jne error
    mov esi, [argv]
    cinvoke strcmp, dword [esi + 4], <'-loadlibrary', 0>
    test eax, eax
    jz loadlibrary
    mov esi, [argv]
    cinvoke strcmp, dword [esi + 4], <'-manual-map', 0>
    test eax, eax
    jz manualmap
    cinvoke printf, <'Wrong injection method! Press enter to continue...', 0>
    cinvoke getchar
    retn

loadlibrary:
    stdcall injectLoadLibraryA
    retn
manualmap:
    stdcall injectManualMap
    retn

error:
    cinvoke printf, <'Wrong amount of Command line arguments! Press enter to continue...', 0>
    cinvoke getchar
    retn

proc injectLoadLibraryA
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    cinvoke strlen, dllPath
    inc eax
    mov [dllPathLength], eax
    mov esi, [argv]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, <cinvoke atoi, dword [esi + 12]>
    mov [processHandle], eax
    invoke VirtualAllocEx, [processHandle], NULL, dllPathLength, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], eax
    invoke WriteProcessMemory, [processHandle], [allocatedMemory], dllPath, [dllPathLength], NULL
    invoke CreateRemoteThread, [processHandle], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, [allocatedMemory], 0, NULL
    invoke WaitForSingleObject, eax, 0xFFFFFFFF
    invoke VirtualFreeEx, [processHandle], [allocatedMemory], dllPathLength, MEM_RELEASE
    invoke CloseHandle, [processHandle]
    ret
endp

proc injectManualMap
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    mov esi, [argv]
    cinvoke atoi, dword [esi + 12]
    cinvoke manualMap, dllPath, eax
    ret
endp

section '.bss' data readable writable

argc    dd ?
argv    dd ?
env     dd ?
dllPath rb MAX_PATH
dllPathLength dd ?
processHandle dd ?
allocatedMemory dd ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll', \
        Inflame, 'Inflame.dll'

import kernel32, \
       GetFullPathNameA, 'GetFullPathNameA', \
       GetModuleHandleA, 'GetModuleHandleA', \
       GetProcAddress, 'GetProcAddress', \
       OpenProcess, 'OpenProcess', \
       VirtualAllocEx, 'VirtualAllocEx', \
       VirtualFreeEx, 'VirtualFreeEx', \
       WriteProcessMemory, 'WriteProcessMemory', \
       CreateRemoteThread, 'CreateRemoteThread', \
       CloseHandle, 'CloseHandle', \
       WaitForSingleObject, 'WaitForSingleObject'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar', \
       strlen, 'strlen', \
       atoi, 'atoi', \
       strcmp, 'strcmp'

import Inflame, \
       manualMap, 'manualMap'
