format PE64 console 6.0
entry main

include 'INCLUDE/win64ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 4
    jne error
    mov rsi, [argv]
    cinvoke strcmp, qword [rsi + 8], <'-loadlibrary', 0>
    cmp rax, 0
    je loadlibrary
    mov rsi, [argv]
    cinvoke strcmp, qword [rsi + 8], <'-manual-map', 0>
    cmp rax, 0
    je manualmap
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
    locals
        dllPath rb MAX_PATH
        dllPathLength dq ?
        processHandle dq ?
        allocatedMemory dq ?
    endl

    mov rsi, [argv]
    lea rax, [dllPath]
    invoke GetFullPathNameA, qword [rsi + 16], MAX_PATH, rax, 0
    lea rax, [dllPath]
    cinvoke strlen, rax
    inc rax
    mov [dllPathLength], rax
    mov rsi, [argv]
    cinvoke atoi, qword [rsi + 24]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, rax
    mov [processHandle], rax
    lea rax, [dllPathLength]
    invoke VirtualAllocEx, [processHandle], NULL, rax, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], rax
    lea rax, [dllPath]
    invoke WriteProcessMemory,[processHandle], [allocatedMemory], rax, [dllPathLength], NULL
    invoke CreateRemoteThread, [processHandle], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, [allocatedMemory], 0, NULL
    invoke WaitForSingleObject, rax, 0xFFFFFFFF
    invoke VirtualFreeEx, [processHandle], [allocatedMemory], qword [dllPathLength], MEM_RELEASE
    invoke CloseHandle, [processHandle]
    ret
endp

proc injectManualMap
    locals
        dllPath rb MAX_PATH
    endl

    mov rsi, [argv]
    lea rax, [dllPath]
    invoke GetFullPathNameA, qword [rsi + 16], MAX_PATH, rax, 0
    mov rsi, [argv]
    cinvoke atoi, qword [rsi + 24]
    lea rbx, [dllPath]
    sub rsp, 8
    cinvoke manualMap, rbx, rax
    ret
endp

section '.bss' data readable writable

argc    dq ?
argv    dq ?
env     dq ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll', \
        Inflame64, 'Inflame64.dll'

import kernel32, \
       CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot', \
       GetFullPathNameA, 'GetFullPathNameA', \
       GetModuleHandleA, 'GetModuleHandleA', \
       GetProcAddress, 'GetProcAddress', \
       OpenProcess, 'OpenProcess', \
       Process32First, 'Process32First', \
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

import Inflame64, \
       manualMap, 'manualMap'
