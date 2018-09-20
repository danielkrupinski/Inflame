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
        allocatedMemory dd ?
        allocatedMemoryEx dd ?
        readBytes dd ?
        processID dd ?
        processHandle dd ?
        loaderMemory
    endl

    mov esi, [argv]
    invoke CreateFileA, dword [esi + 4], GENERIC_READ, FILE_SHARE_READ + FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    mov [dllHandle], eax
    invoke GetFileSize, eax, NULL
    mov [dllSize], eax
    invoke VirtualAlloc, NULL, eax, MEM_COMMIT + MEM_RESERVE, PAGE_READWRITE
    mov [allocatedMemory], eax
    lea eax, [dllHandle]
    lea ebx, [allocatedMemory]
    lea ecx, [dllSize]
    lea edx, [readBytes]
    invoke ReadFile, eax, ebx, ecx, edx, NULL
    lea eax, [dllHandle]
    invoke CloseHandle, eax

    virtual at allocatedMemory
        dllDOSHeader IMAGE_DOS_HEADER
    end virtual

    virtual at allocatedMemory + IMAGE_DOS_HEADER.e_lfanew
        dllNTHeaders IMAGE_NT_HEADERS
    end virtual

    mov esi, [argv]
    cinvoke atoi, dword [esi + 8]
    mov [processID], eax
    invoke OpenProcess, PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD, FALSE, eax
    mov [processHandle], eax
    lea eax, [processHandle]
    invoke VirtualAllocEx, dword [eax], NULL, dllNTHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE
    mov [allocatedMemoryEx], eax
    lea ebx, [processHandle]
    lea ecx, [allocatedMemory]
    invoke WriteProcessMemory, dword [ebx], dword [eax], dword [ecx], dllNTHeaders.OptionalHeader.SizeOfHeaders, NULL

    virtual at dllNTHeaders + 1
        dllSectionHeader IMAGE_SECTION_HEADER
    end virtual

    xor ecx, ecx
    loop1:
        virtual at dllSectionHeader + (sizeof.IMAGE_SECTION_HEADER * ecx)
            sectionHeader IMAGE_SECTION_HEADER
        end virtual

        lea eax, [processHandle]
        lea ebx, [allocatedMemoryEx]
        lea edx, [allocatedMemory]
        push ecx
        invoke WriteProcessMemory, dword [eax], dword [ebx + sectionHeader.VirtualAddress], dword [edx + sectionHeader.OffsetToRawData], sectionHeader.SizeOfRawData, NULL
        pop ecx
        inc ecx
        cmp ecx, [dllNTHeaders.FileHeader.NumberOfSections]
        jl loop1
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
       GetFileSize, 'GetFileSize', \
       VirtualAlloc, 'VirtualAlloc', \
       ReadFile, 'ReadFile'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar', \
       strlen, 'strlen', \
       atoi, 'atoi'
