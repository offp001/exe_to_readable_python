# exetopy 0.3.0

exetopy extracts Python bytecode from a PyInstaller executable, writes a `.pyasm` disassembly for every extracted `.pyc`, and recovers readable `.py` source from the matching bytecode with PyCDC. It also converts every discovered `.pyasm` file and keeps the original `.pyc` files.

<p align="center">
  <img src="https://img.shields.io/github/license/offp001/routils" alt="RoUtils License">
</p>

## usage

Run this command from the directory containing the executable:

```bash
python3 exetopy.py filename.exe
```

The `.exe` suffix may be omitted:

```bash
python3 exetopy.py filename
```

Interactive mode is available too:

```bash
python3 exetopy.py
```

The extracted files are placed in `filename.exe_extracted`.

## processing

1. Locate the input PyInstaller executable.
2. Run `pyinstxtractor.py` and preserve the extracted files.
3. Find every extracted `.pyc` file, excluding `_fixed.pyc` files.
4. Disassemble each `.pyc` into a corresponding `.pyasm` file. The local CPython `dis` module is used when its bytecode version matches; otherwise PyCDC disassembly is used.
5. Recursively find every `.pyasm` file in the extraction directory.
6. Match each `.pyasm` to its original `.pyc` and recover readable `.py` source with PyCDC.
7. Create `all_functions_disasm.txt` and `exetopy_report.json`.

Each recovered `.py` file starts with a source marker such as:

```python
# source: module.pyasm
```

The original `.pyc` files are never deleted.

## requirements

- Python 3.10 or newer
- Internet access on first run, unless the required tools are already cached or available locally

The Python code uses only the standard library. On first run, ExeToPy downloads:

- `pyinstxtractor.py` from the upstream PyInstaller extractor project
- PyCDC v0.8.0 for Linux x86_64 or aarch64

The PyCDC executable is checked against its configured SHA-256 digest and stored in `~/.cache/exetopy/`.

## options

The basic command is:

```bash
python3 exetopy.py filename.exe
```

Optional arguments:

```text
--pycdc PATH       use a specific PyCDC executable
--extractor PATH   use a local pyinstxtractor.py script
--no-download      do not download missing tools
--no-cure          disable PyCDC's optional source cleanup
--reextract        replace an existing extraction directory
--strict           return a nonzero status if any file fails
--version          print the version
```

Examples:

```bash
python3 exetopy.py filename.exe --reextract
python3 exetopy.py filename.exe --pycdc /usr/local/bin/pycdc
python3 exetopy.py filename.exe --extractor ./pyinstxtractor.py
```

## output

```text
filename.exe_extracted/
  module.pyc
  module.pyasm
  module.py
  all_functions_disasm.txt
  exetopy_report.json
```

Actual files and subdirectories depend on the executable.

## limitations

Readable source is reconstructed from the matching `.pyc`, not guessed from `.pyasm` text. A disassembly listing does not preserve comments, original formatting, all variable names, or every source-level choice. If a `.pyasm` has no matching `.pyc`, its original function bodies cannot reliably be recovered from the listing alone; the report records that failure instead of fabricating source code.

PyCDC may not reconstruct malformed, customized, packed, or unsupported bytecode. Decompiled source is not guaranteed to be identical to the original or to run without modification. Review recovered code before using it, and do not execute source recovered from an untrusted executable.

## tests

```bash
python3 -m py_compile exetopy.py
python3 -m unittest discover -s tests -v
```

## upstream projects

- PyCDC: https://github.com/ejfkdev/pycdc
- PyInstaller extractor: https://github.com/extremecoders-re/pyinstxtractor
- Python disassembly reference: https://docs.python.org/3/library/dis.html

<p align="center">
  <sub>by offp001</sub>
</p>
