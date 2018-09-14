format PE64 console

include 'INCLUDE/win64ax.inc'

section '.idata' data readable import

library kernel32, 'kernel32.dll', \
        msvcrt, 'msvcrt.dll'
