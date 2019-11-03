format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

struct PROCESSENTRY32
       dwSize                  dd ?
       cntUsage                dd ?
       th32ProcessID           dd ?
       th32DefaultHeapID       dd ?
       th32ModuleID            dd ?
       cntThreads              dd ?
       th32ParentProcessID     dd ?
       pcPriClassBase          dd ?
       dwFlags                 dd ?
       szExeFile               dw MAX_PATH dup (?)
ends

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

proc findProcessId, name
    local snapshot:DWORD, processEntry:PROCESSENTRY32

    invoke CreateToolhelp32Snapshot, 0x2, 0
    mov [snapshot], eax
    mov [processEntry.dwSize], sizeof.PROCESSENTRY32
    lea eax, [processEntry]
    invoke Process32First, [snapshot], eax
    test eax, eax
    jz .error
    
    .loop1:
        lea eax, [processEntry.szExeFile]
        cinvoke strcmp, eax, [name]
        test eax, eax
        jz .return
        lea eax, [processEntry]
        invoke Process32Next, [snapshot], eax
        test eax, eax
        jnz .loop1

    .error:
        xor eax, eax
        ret

    .return:
        mov eax, [processEntry.th32ProcessID]
        ret
endp

loadlibrary:
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    cinvoke strlen, dllPath
    inc eax
    mov [dllPathLength], eax
    mov esi, [argv]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, <stdcall findProcessId, dword [esi + 12]>
    mov [processHandle], eax
    invoke VirtualAllocEx, [processHandle], NULL, dllPathLength, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], eax
    invoke WriteProcessMemory, [processHandle], [allocatedMemory], dllPath, [dllPathLength], NULL
    invoke CreateRemoteThread, [processHandle], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, [allocatedMemory], 0, NULL
    invoke WaitForSingleObject, eax, 0xFFFFFFFF
    invoke VirtualFreeEx, [processHandle], [allocatedMemory], dllPathLength, MEM_RELEASE
    invoke CloseHandle, [processHandle]
    retn

manualmap:
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    mov esi, [argv]
    cinvoke manualMap, dllPath, <stdcall findProcessId, dword [esi + 12]>
    retn

error:
    cinvoke printf, <'Wrong amount of Command line arguments! Press enter to continue...', 0>
    cinvoke getchar
    retn

manualmap_2:
    mov esi, [argv]
    invoke GetFullPathNameA, dword [esi + 8], MAX_PATH, dllPath, 0
    invoke CreateFileA, dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    retn

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
       CreateFileA, 'CreateFileA', \
       CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot', \
       GetFullPathNameA, 'GetFullPathNameA', \
       GetModuleHandleA, 'GetModuleHandleA', \
       GetProcAddress, 'GetProcAddress', \
       OpenProcess, 'OpenProcess', \
       Process32First, 'Process32First', \
       Process32Next, 'Process32Next', \
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
