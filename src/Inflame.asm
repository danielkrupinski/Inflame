format PE console 6.0
entry main

include 'INCLUDE/win32ax.inc'

struct IMAGE_DATA_DIRECTORY
    .VirtualAddress dd  ?
    .isize          dd  ?
ends

struct IMAGE_OPTIONAL_HEADER32
    .Magic                         dw  ?
    .MajorLinkerVersion            db  ?
    .MinorLinkerVersion            db  ?
    .SizeOfCode                    dd  ?
    .SizeOfInitializedData         dd  ?
    .SizeOfUninitializedData       dd  ?
    .AddressOfEntryPoint           dd  ?
    .BaseOfCode                    dd  ?
    .BaseOfData                    dd  ?
    .ImageBase                     dd  ?
    .SectionAlignment              dd  ?
    .FileAlignment                 dd  ?
    .MajorOperatingSystemVersion   dw  ?
    .MinorOperatingSystemVersion   dw  ?
    .MajorImageVersion             dw  ?
    .MinorImageVersion             dw  ?
    .MajorSubsystemVersion         dw  ?
    .MinorSubsystemVersion         dw  ?
    .Win32VersionValue             dd  ?
    .SizeOfImage                   dd  ?
    .SizeOfHeaders                 dd  ?
    .CheckSum                      dd  ?
    .Subsystem                     dw  ?
    .DllCharacteristics            dw  ?
    .SizeOfStackReserve            dd  ?
    .SizeOfStackCommit             dd  ?
    .SizeOfHeapReserve             dd  ?
    .SizeOfHeapCommit              dd  ?
    .LoaderFlags                   dd  ?
    .NumberOfRvaAndSizes           dd  ?
    .DataDirectory                 rb (sizeof.IMAGE_DATA_DIRECTORY * 16)
ends

struct IMAGE_FILE_HEADER
    .Machine               dw ?
    .NumberOfSections      dw ?
    .TimeDateStamp         dd ?
    .PointerToSymbolTable  dd ?
    .NumberOfSymbols       dd ?
    .SizeOfOptionalHeader  dw ?
    .Characteristics       dw ?
ends

struct IMAGE_NT_HEADERS
    .Signature         dd ?
    .FileHeader        IMAGE_FILE_HEADER
    .OptionalHeader    IMAGE_OPTIONAL_HEADER32
ends

struct IMAGE_EXPORT_DIRECTORY
    .Characteristics       dd  ?
    .TimeDateStamp         dd  ?
    .MajorVersion          dw  ?
    .MinorVersion          dw  ?
    .nName                 dd  ?
    .nBase                 dd  ?
    .NumberOfFunctions     dd  ?
    .NumberOfNames         dd  ?
    .AddressOfFunctions    dd  ?
    .AddressOfNames        dd  ?
    .AddressOfNameOrdinals dd  ?
ends

struct IMAGE_DOS_HEADER
    .e_magic           dw ?
    .e_cblp            dw ?
    .e_cp              dw ?
    .e_crlc            dw ?
    .e_cparhdr         dw ?
    .e_minalloc        dw ?
    .e_maxalloc        dw ?
    .e_ss              dw ?
    .e_sp              dw ?
    .e_csum            dw ?
    .e_ip              dw ?
    .e_cs              dw ?
    .e_lfarlc          dw ?
    .e_ovno            dw ?
    .e_res             rw 4
    .e_oemid           dw ?
    .e_oeminfo         dw ?
    .e_res2            rw 10
    .e_lfanew          dd ?
ends

struct IMAGE_SECTION_HEADER
    .Name                 rb 8
    .VirtualSize          dd ?
    .VirtualAddress       dd ?
    .SizeOfRawData        dd ?
    .OffsetToRawData      dd ?
    .OffsetToRelocations  dd ?
    .OffsetToLinenumbers  dd ?
    .NumberOfRelocations  dw ?
    .NumberOfLinenumbers  dw ?
    .Characteristics      dd ?
ends

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
