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
    invoke ExitProcess, 1

loadlibrary:
    stdcall injectLoadLibraryA
    invoke ExitProcess, 0

manualmap:
    stdcall injectManualMap
    invoke ExitProcess, 0

error:
    cinvoke printf, <'Wrong amount of Command line arguments! Press enter to continue...', 0>
    cinvoke getchar
    invoke ExitProcess, 1

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
    lea rbx, [processHandle]
    invoke VirtualAllocEx, qword [rbx], NULL, rax, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], rax
    lea rax, [dllPath]
    lea rbx, [dllPathLength]
    lea rcx, [processHandle]
    lea rdx, [allocatedMemory]
    invoke WriteProcessMemory, qword [rcx], qword [rdx], rax, qword [rbx], NULL
    lea rbx, [processHandle]
    lea rsi, [allocatedMemory]
    invoke CreateRemoteThread, qword [rbx], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, qword [rsi], 0, NULL
    lea rax, [processHandle]
    invoke CloseHandle, qword [rax]
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
       ExitProcess, 'ExitProcess', \
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

import Inflame64, \
       manualMap, 'manualMap'
