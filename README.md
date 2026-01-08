# pedump

pedump is a command-line tool that helps you analyze Windows's Portable Executable files by parsing and printing the required information about them.

This project is currently a work in progress so not everything is supported, and it might be broken.

pedump might evolve into a library later, instead of just being a standalone command-line tool.

## Usage

```
Usage: pedump.exe [OPTIONS] <FILE_PATH>

Arguments:
  <FILE_PATH>

Options:
      --dos-header
          Dumps the legacy MS-DOS compatible header
      --nt-header
          Dumps the NT Header (most recent)
      --optional-header
          Dumps the Optional (either 32/64) header
      --sections
          Dumps the Sections
      --sections-filter <SECTIONS_FILTER>
          Regulax expresion to filter the Sections to display [default: .*]
      --sections-data
          Dumps the Sections data along with the headers
      --disasm
          Disassemble the code found in the Sections containing code
      --import
          Dump all the data related to imports, if any
      --import-directory-table
          Dump the Import Directory Table, if any
      --hint-name-table
          Dump the Hint/Name Table, if any
      --dlls
          Dump the DLLs names imported, if any
      --debug
          Dump the debug information from the Debug Directory, if any
      --exception
          Dump the exception information from the Exception Table, if any
      --padding-size <PADDING_SIZE>
          Padding size to apply when dumping information for better readability [default: 4]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Features

Headers:

- :heavy_check_mark: DOS
- :heavy_check_mark: NT-Header (and COFF Header)
- :heavy_check_mark: Optional Header (32-bit and 64-bit)

Sections:

- :x: Export Table
- :heavy_check_mark: Import Table
- :x: Resource Table
- :heavy_check_mark: Exception Table
- :x: Certificate Table
- :x: Base Relocation Table
- :heavy_check_mark: Debug
- :x: TLS Table
- :x: Load Config Table
- :x: Bound Import Table
- :x: Import Address Table
- :x: Delay Import Descriptor
- :x: CLR Runtime Header

Code:

- :heavy_check_mark: Basic disassembly of the code sections
