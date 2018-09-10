format PE console
entry main

include 'win32ax.inc'

section '.text' code executable
main:

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'

import kernel32, \
       ExitProcess, 'ExitProcess'
