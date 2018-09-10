format PE console
entry main

include 'win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 3
    jne error
    mov esi,[argv]
    cinvoke printf, dword [esi]
    cinvoke getchar
    invoke ExitProcess, 0

error:
    invoke ExitProcess, 1

section '.data' data readable writable

argc    dd ?
argv    dd ?
env     dd ?

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'

import kernel32, \
       ExitProcess, 'ExitProcess'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar'
