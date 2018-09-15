# Inflame

User-mode Windows DLL injector written in Assembly (FASM) with WINAPI

## Features

- **minimal size:** weighing `2kB`, Inflame is a tiny little injector
- **lightning fast:** Inflame execution takes less than `25ms`
- **easy to use:** invoked with Command Line options
- **universal:** both `32-bit` and `64-bit` versions are maintained

## Getting Started

### Prerequisites

FASM (flat assembler) for Windows is required to compile Inflame. You can get the latest version [here](https://flatassembler.net/download.php).

### Installing

Inflame is available in 2 versions:

* `32-bit` - `Inflame.asm` - for both 32-bit dll and destination process
* `64-bit` - `Inflame64.asm` - for both 64-bit dll and destination process

1. Choose correct Inflame version based on dll and destination process architecture. See above.
1. Copy chosen `.asm` file to same directory as `FASM.EXE`.
1. Open cmd.exe there and enter following command:
```
fasm Inflame.asm
```
or
```
fasm Inflame64.asm
```
1. If everything went right you should see output similar to this one:
```
flat assembler  version 1.73.04  (1048576 kilobytes memory)
3 passes, 1536 bytes.
```
and output executable `Inflame.exe` should exist.
1. Then run `Inflame.exe` using this syntax:
```
Inflame [path to dll or dll name when in the same folder] [destination process ID]
```
Valid command should look like this one:
```
Inflame test.dll 1024
```


## License

> Copyright (c) 2018 Daniel Krupiński

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
