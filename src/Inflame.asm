format PE console
entry main

include 'win32ax.inc'

section '.text' code executable

main:
    cinvoke __getmainargs, argc, argv, env, 0
    cmp [argc], 3
    jne error
    stdcall inject
    invoke ExitProcess, 0

error:
    invoke ExitProcess, 1

proc inject

    ret
endp

section '.data' data readable writable

argc    dd ?
argv    dd ?
env     dd ?
dllPath rb 260

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'

import kernel32, \
       ExitProcess, 'ExitProcess', \
       GetFullPathNameA, 'GetFullPathNameA'

import msvcrt, \
       __getmainargs, '__getmainargs', \
       printf, 'printf', \
       getchar, 'getchar'
