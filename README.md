# Inflame

User-mode Windows DLL injector written in Assembly (FASM) with WINAPI

## Features

- **minimal size:** weighing `2kB`, Inflame is a tiny little injector
- **lightning fast:** injection takes less than `25ms`

## Getting Started

### Prerequisites

FASM (flat assembler) for Windows is required to compile Inflame. You can get the latest version [here](https://flatassembler.net/download.php).

### Installing

1. Copy Inflame.asm to directory where you extracted FASM.
2. Open cmd.exe there and enter following command:
```
fasm Inflame.asm
```
3. If everything went right you should see output similar to this one:
```
flat assembler  version 1.73.04  (1048576 kilobytes memory)
3 passes, 1536 bytes.
```
and output executable `Inflame.exe` should exist.

## License

> Copyright (c) 2018 Daniel Krupiński

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
