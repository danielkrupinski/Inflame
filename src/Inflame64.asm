format PE64 console

include 'INCLUDE/win64ax.inc'

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
