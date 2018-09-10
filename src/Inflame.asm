format PE console
entry main

include 'win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0

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
