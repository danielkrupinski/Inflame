format PE64 console
entry main

include 'INCLUDE/win64ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 3
    jne error
    stdcall inject
    invoke ExitProcess, 0

error:
    cinvoke printf, <'Wrong amount of Command Line arguments! Press enter to continue...', 0>
    cinvoke getchar
    invoke ExitProcess, 1

proc inject
    mov rsi, [argv]
    invoke GetFullPathNameA, qword [rsi + 8], MAX_PATH, dllPath, 0
    cinvoke strlen, dllPath
    inc rax
    mov [dllPathLength], rax
    mov rsi, [argv]
    cinvoke atoi, qword [esi + 16]
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_QUERY_INFORMATION + PROCESS_CREATE_THREAD, FALSE, rax
    mov [processHandle], rax
    invoke VirtualAllocEx, [processHandle], NULL, [dllPathLength], MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], rax
    invoke WriteProcessMemory, [processHandle], [allocatedMemory], dllPath, [dllPathLength], NULL
    invoke CreateRemoteThread, [processHandle], NULL, 0, <invoke GetProcAddress, <invoke GetModuleHandleA, <'kernel32.dll', 0>>, <'LoadLibraryA', 0>>, [allocatedMemory], 0, NULL
    invoke CloseHandle, [processHandle]
    ret
endp

section '.data' data readable writable

argc    dq ?
argv    dq ?
env     dq ?
dllPath rb MAX_PATH
dllPathLength dq ?
processHandle dq ?
allocatedMemory dq ?

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
       CloseHandle, 'CloseHandle'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar', \
       strlen, 'strlen', \
       atoi, 'atoi'
