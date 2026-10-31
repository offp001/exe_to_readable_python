import argparse
import dis
import hashlib
import importlib.util
import io
import json
import marshal
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from pathlib import Path

version = "0.3.0"
pycdc_release = "v0.8.0"
cache_dir = Path.home() / ".cache" / "exetopy"
pyinstxtractor_url = "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py"
pycdc_assets = {
    "x86_64": (
        "https://github.com/ejfkdev/pycdc/releases/download/v0.8.0/pycdc-x86_64-linux",
        "99bc1a8f0818ff265d49ff57e2168f931e9604fa7cd2823fcf7b34f118a139b6",
    ),
    "aarch64": (
        "https://github.com/ejfkdev/pycdc/releases/download/v0.8.0/pycdc-aarch64-linux",
        "9c1ce5651b706f2a7e266d8b97f357cc4aff914048f7c2af25ff1386c5768b9d",
    ),
}
label_pattern = re.compile(r"^L\d+:?$", re.IGNORECASE)
opcode_pattern = re.compile(r"^[A-Z][A-Z0-9_]*$")
argument_pattern = re.compile(r"^(-?\d+)(?:\s+\((.*)\))?$")
code_object_pattern = re.compile(r"<code object\s+([^, >]+)")
source_header_pattern = re.compile(r"^#\s*source:\s*(.+?)\s*$", re.IGNORECASE)
ignored_headers = {
    "DISASSEMBLY", "EXCEPTIONTABLE", "NAME", "FILENAME", "FLAGS", "CONSTANTS",
    "NAMES", "VARIABLES", "FREEVARS", "CELLVARS", "STACKSIZE", "ARGUMENTS",
}


def parse_instruction_line(raw, line_number):
    stripped = raw.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return None, None
    lowered = stripped.lower()
    if lowered.startswith(("disassembly of ", "exceptiontable:", "name:", "filename:")):
        return None, None
    parts = stripped.split()
    labels = []
    index = 0
    numeric_prefix = []
    while index < len(parts):
        token = parts[index]
        if token in {"-->", ">>", "->"}:
            index += 1
            continue
        if label_pattern.fullmatch(token):
            labels.append(token.rstrip(":"))
            index += 1
            continue
        if token in {"--", "-"} or token.isdigit():
            numeric_prefix.append(token)
            index += 1
            continue
        break
    if index >= len(parts):
        if labels:
            return {"labels": labels}, None
        return None, line_number
    opcode = parts[index]
    if not opcode_pattern.fullmatch(opcode):
        return None, line_number
    if opcode in ignored_headers:
        return None, None
    operand = stripped[stripped.find(opcode) + len(opcode):].strip()
    numeric_arg = None
    annotation = ""
    if operand:
        match = argument_pattern.fullmatch(operand)
        if match:
            numeric_arg = int(match.group(1))
            annotation = (match.group(2) or "").strip()
        else:
            annotation = operand
    return {
        "opcode": opcode,
        "arg": numeric_arg,
        "annotation": annotation,
        "operand": operand,
        "line": line_number,
        "source_line": numeric_prefix[0] if numeric_prefix else None,
        "offset": numeric_prefix[1] if len(numeric_prefix) > 1 else None,
        "labels": labels,
    }, None


def parse_disassembly(source):
    instructions = []
    pending_labels = []
    ignored = []
    for line_number, raw in enumerate(source.splitlines(), 1):
        instruction, ignored_line = parse_instruction_line(raw, line_number)
        if instruction is None:
            if ignored_line is not None:
                ignored.append(ignored_line)
            continue
        if "opcode" not in instruction:
            pending_labels.extend(instruction.get("labels", []))
            continue
        instruction["labels"] = pending_labels + instruction["labels"]
        pending_labels = []
        instructions.append(instruction)
    return instructions, ignored, pending_labels


def scan_disassembly(path, sample_limit=12):
    path = Path(path)
    instruction_count = 0
    label_count = 0
    ignored_count = 0
    ignored_lines = []
    code_objects = []
    source_marker = False
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, raw in enumerate(stream, 1):
            if line_number == 1 and source_header_pattern.match(raw.rstrip("\r\n")):
                source_marker = True
            for match in code_object_pattern.finditer(raw):
                name = match.group(1)
                if name not in code_objects:
                    code_objects.append(name)
            instruction, ignored_line = parse_instruction_line(raw, line_number)
            if instruction is None:
                if ignored_line is not None:
                    ignored_count += 1
                    if len(ignored_lines) < sample_limit:
                        ignored_lines.append(ignored_line)
                continue
            if "opcode" not in instruction:
                label_count += len(instruction.get("labels", []))
                continue
            instruction_count += 1
            label_count += len(instruction.get("labels", []))
    return {
        "format": "cpython disassembly" if instruction_count else "unknown",
        "instructions": instruction_count,
        "labels": label_count,
        "ignored_lines": ignored_count,
        "ignored_line_samples": ignored_lines,
        "code_objects_referenced": len(code_objects),
        "code_object_names": code_objects,
        "source_marker": source_marker,
        "file_size": path.stat().st_size,
    }


def print_error(message):
    print(f"error: {message}", file=sys.stderr)


def tail_text(stream, limit=12000):
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(max(0, size - limit))
    return stream.read().decode("utf-8", errors="replace").strip()


def download_file(url, destination, expected_hash=None, maximum=30 * 1024 * 1024):
    from urllib.request import Request, urlopen

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(url, headers={"User-Agent": f"exetopy/{version}"})
    digest = hashlib.sha256()
    total = 0
    temporary = destination.with_name(destination.name + ".download")
    try:
        with urlopen(request, timeout=90) as response, temporary.open("wb") as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise RuntimeError("download exceeded the size limit")
                digest.update(block)
                output.write(block)
        actual_hash = digest.hexdigest()
        if expected_hash and actual_hash != expected_hash:
            raise RuntimeError(f"sha256 mismatch: expected {expected_hash}, received {actual_hash}")
        temporary.replace(destination)
        return actual_hash
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def find_pycdc(requested=None, allow_download=True):
    if requested:
        candidate = Path(requested).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        found = shutil.which(requested)
        if found:
            return found
        raise RuntimeError(f"pycdc executable was not found: {requested}")
    found = shutil.which("pycdc")
    if found:
        return found
    if not allow_download:
        return None
    machine = platform.machine().lower()
    asset = pycdc_assets.get(machine)
    if not asset:
        raise RuntimeError(f"automatic pycdc download is unavailable for architecture: {machine}")
    url, expected_hash = asset
    destination = cache_dir / f"pycdc-{pycdc_release}-{machine}"
    if destination.is_file():
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest == expected_hash:
            return str(destination)
        destination.unlink(missing_ok=True)
    print("downloading verified pycdc decompiler...")
    download_file(url, destination, expected_hash=expected_hash, maximum=20 * 1024 * 1024)
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(destination)


def find_pyinstxtractor(requested=None, allow_download=True):
    if requested:
        candidate = Path(requested).expanduser()
        if not candidate.is_file():
            raise RuntimeError(f"pyinstxtractor script was not found: {requested}")
        return candidate.resolve()
    candidates = (Path.cwd() / "pyinstxtractor.py", Path(__file__).with_name("pyinstxtractor.py"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    if not allow_download:
        raise RuntimeError("pyinstxtractor.py was not found; pass --extractor or enable downloads")
    destination = cache_dir / "pyinstxtractor.py"
    if destination.is_file():
        content = destination.read_text(encoding="utf-8", errors="replace")
        if "PyInstaller" in content and "PYZ" in content:
            return destination
        destination.unlink(missing_ok=True)
    print("downloading pyinstaller extractor...")
    download_file(pyinstxtractor_url, destination, maximum=10 * 1024 * 1024)
    content = destination.read_text(encoding="utf-8", errors="replace")
    if "PyInstaller" not in content or "PYZ" not in content:
        destination.unlink(missing_ok=True)
        raise RuntimeError("the downloaded extractor failed its content check")
    return destination


def run_tool_to_file(command, output_path, timeout=600):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            [str(part) for part in command],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
        )
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError(f"command timed out after {timeout} seconds")
        error_text = tail_text(errors)
    return return_code, error_text


def run_tool(command, timeout=180):
    result = subprocess.run(
        [str(part) for part in command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return result


def current_python_code(pyc_path, maximum_size=64 * 1024 * 1024):
    pyc_path = Path(pyc_path)
    if pyc_path.stat().st_size > maximum_size:
        return None
    with pyc_path.open("rb") as stream:
        header = stream.read(16)
        if len(header) < 16 or header[:4] != importlib.util.MAGIC_NUMBER:
            return None
        data = stream.read()
    try:
        code = marshal.loads(data)
    except Exception:
        return None
    return code if isinstance(code, types.CodeType) else None


def native_disassemble(pyc_path):
    code = current_python_code(pyc_path)
    if code is None:
        return None
    output = io.StringIO()
    try:
        dis.dis(code, file=output, depth=None)
    except TypeError:
        dis.dis(code, file=output)
    return output.getvalue()


def pycdc_disassemble(pycdc, pyc_path, output_path):
    attempts = ([pycdc, "dis", pyc_path], [pycdc, pyc_path, "--disassemble"])
    failures = []
    for command in attempts:
        try:
            return_code, error_text = run_tool_to_file(command, output_path, timeout=900)
        except (OSError, RuntimeError) as exc:
            failures.append(str(exc))
            continue
        if return_code == 0 and Path(output_path).stat().st_size:
            return True
        failures.append(error_text or f"exit code {return_code}")
    raise RuntimeError("pycdc could not disassemble this pyc: " + " | ".join(failures))


def write_text_atomic(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    temporary.replace(path)


def write_python_from_file(source_path, output_path, source_name):
    source_path = Path(source_path)
    output_path = Path(output_path)
    if not source_path.is_file() or source_path.stat().st_size == 0:
        raise RuntimeError("the decompiler returned an empty source file")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    with source_path.open("rb") as source, temporary.open("wb") as output:
        output.write(f"# source: {source_name}\n\n".encode("utf-8"))
        shutil.copyfileobj(source, output, length=1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(output_path)


def pycdc_source(pycdc, pyc_path, output_path, source_name, use_cure=True):
    output_path = Path(output_path)
    temporary = output_path.with_name(output_path.name + ".pycdc.tmp")
    commands = []
    if use_cure:
        commands.append([pycdc, "--cure", pyc_path])
    commands.append([pycdc, pyc_path])
    failures = []
    for command in commands:
        try:
            return_code, error_text = run_tool_to_file(command, temporary, timeout=1800)
        except (OSError, RuntimeError) as exc:
            failures.append(str(exc))
            continue
        if return_code == 0 and temporary.is_file() and temporary.stat().st_size:
            write_python_from_file(temporary, output_path, source_name)
            temporary.unlink(missing_ok=True)
            return output_path
        failures.append(error_text or f"exit code {return_code}")
        temporary.unlink(missing_ok=True)
    raise RuntimeError("pycdc could not reconstruct source: " + " | ".join(failures))


def write_disassembly(disassembly, output_path, source_name):
    output_path = Path(output_path)
    temporary = output_path.with_name(output_path.name + ".tmp")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        output.write(f"# source: {source_name}\n\n")
        output.write(disassembly.rstrip())
        output.write("\n")
    temporary.replace(output_path)


def write_disassembly_from_file(disassembly_path, output_path, source_name):
    disassembly_path = Path(disassembly_path)
    output_path = Path(output_path)
    temporary = output_path.with_name(output_path.name + ".tmp")
    with disassembly_path.open("rb") as source, temporary.open("wb") as output:
        output.write(f"# source: {source_name}\n\n".encode("utf-8"))
        shutil.copyfileobj(source, output, length=1024 * 1024)
    temporary.replace(output_path)


def process_pyc(pyc_path, pycdc, use_cure=True, output_path=None):
    pyc_path = Path(pyc_path)
    output_path = Path(output_path) if output_path else pyc_path.with_suffix(".py")
    disassembly_path = pyc_path.with_suffix(".pyasm")
    result = {"pyc": str(pyc_path), "python": None, "pyasm": None, "errors": []}
    disassembly = native_disassemble(pyc_path)
    if disassembly is not None:
        write_disassembly(disassembly, disassembly_path, pyc_path.name)
        result["pyasm"] = str(disassembly_path)
    elif pycdc:
        temporary_disassembly = disassembly_path.with_name(disassembly_path.name + ".raw")
        try:
            pycdc_disassemble(pycdc, str(pyc_path), temporary_disassembly)
            write_disassembly_from_file(temporary_disassembly, disassembly_path, pyc_path.name)
            temporary_disassembly.unlink(missing_ok=True)
            result["pyasm"] = str(disassembly_path)
        except Exception as exc:
            temporary_disassembly.unlink(missing_ok=True)
            result["errors"].append(f"disassembly: {exc}")
    try:
        if not pycdc:
            raise RuntimeError("pycdc is required for readable source reconstruction")
        source_name = disassembly_path.name if result["pyasm"] else pyc_path.name
        pycdc_source(pycdc, str(pyc_path), output_path, source_name, use_cure=use_cure)
        result["python"] = str(output_path)
    except Exception as exc:
        result["errors"].append(f"decompilation: {exc}")
    return result


def read_source_reference(pyasm_path):
    try:
        with Path(pyasm_path).open("r", encoding="utf-8", errors="replace") as stream:
            first_line = stream.readline().strip()
    except OSError:
        return None
    match = source_header_pattern.match(first_line)
    if not match:
        return None
    return match.group(1)


def matching_pyc(pyasm_path):
    pyasm_path = Path(pyasm_path).resolve()
    direct = pyasm_path.with_suffix(".pyc")
    if direct.is_file():
        return direct
    reference = read_source_reference(pyasm_path)
    if reference and reference.lower().endswith(".pyc"):
        referenced = Path(reference).expanduser()
        candidates = [referenced]
        if not referenced.is_absolute():
            candidates.insert(0, pyasm_path.parent / referenced)
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
    stem = pyasm_path.stem
    search_roots = [pyasm_path.parent, pyasm_path.parent / "__pycache__"]
    for root in search_roots:
        if not root.is_dir():
            continue
        exact = root / f"{stem}.pyc"
        if exact.is_file():
            return exact.resolve()
        try:
            candidates = sorted(root.glob(f"{stem}.*.pyc"))
        except OSError:
            candidates = []
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
    return None


def find_adjacent_executable(pyasm_path):
    pyasm_path = Path(pyasm_path).resolve()
    stem = pyasm_path.stem.lower()
    search_roots = [pyasm_path.parent, pyasm_path.parent.parent]
    for root in search_roots:
        if not root.is_dir():
            continue
        try:
            for candidate in root.iterdir():
                if candidate.is_file() and candidate.suffix.lower() == ".exe" and candidate.stem.lower() == stem:
                    return candidate.resolve()
        except OSError:
            continue
    return None


def find_executable_file(input_value):
    candidate = Path(input_value).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    if not candidate.suffix:
        parent = candidate.parent if str(candidate.parent) else Path(".")
        if parent.is_dir():
            for item in parent.iterdir():
                if item.is_file() and item.name.lower() == (candidate.name + ".exe").lower():
                    return item.resolve()
    return None


def extract_exe(exe_path, extractor_path, reextract=False):
    exe_path = Path(exe_path).resolve()
    output_dir = Path(str(exe_path) + "_extracted")
    if output_dir.is_dir() and not reextract:
        print(f"using existing extraction directory: {output_dir}")
        return output_dir
    if output_dir.is_dir() and reextract:
        shutil.rmtree(output_dir)
    result = run_tool([sys.executable, extractor_path, exe_path], timeout=1800)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
        raise RuntimeError("pyinstxtractor failed: " + detail[-3000:])
    if not output_dir.is_dir():
        raise RuntimeError("pyinstxtractor finished but the extraction directory was not created")
    return output_dir


def print_scan_summary(path):
    summary = scan_disassembly(path)
    print(f"format: {summary['format']}")
    print(f"instructions: {summary['instructions']}")
    print(f"labels: {summary['labels']}")
    if summary["code_objects_referenced"]:
        print(f"referenced code objects: {summary['code_objects_referenced']}")
    return summary


def convert_pyasm(pyasm_path, output_path, pycdc=None, use_cure=True):
    pyasm_path = Path(pyasm_path).resolve()
    output_path = Path(output_path).resolve() if output_path else pyasm_path.with_suffix(".py")
    summary = print_scan_summary(pyasm_path)
    if summary["format"] != "cpython disassembly":
        raise RuntimeError("the input does not contain recognizable cpython disassembly instructions")
    paired_pyc = matching_pyc(pyasm_path)
    if paired_pyc is None:
        adjacent_exe = find_adjacent_executable(pyasm_path)
        if adjacent_exe is not None:
            print(f"matching executable found: {adjacent_exe.name}")
            raise RuntimeError(
                f"matching executable found; extract it with: python3 exetopy.py {adjacent_exe.name}"
            )
        referenced = summary["code_objects_referenced"]
        detail = "the .pyasm file contains bytecode instructions, not the original code objects"
        if referenced:
            detail += f"; {referenced} nested code-object references were found"
        raise RuntimeError(
            detail + "; provide the matching .pyc file or re-extract the original pyinstaller executable"
        )
    if not pycdc:
        raise RuntimeError("pycdc is required; install it or allow the automatic verified download")
    print(f"matched bytecode: {paired_pyc.name}")
    pycdc_source(pycdc, str(paired_pyc), output_path, pyasm_path.name, use_cure=use_cure)
    return {"pyc": str(paired_pyc), "python": str(output_path), "pyasm": str(pyasm_path), "errors": []}


def create_pyasm_from_pyc(pyc_path, pycdc):
    pyc_path = Path(pyc_path)
    pyasm_path = pyc_path.with_suffix(".pyasm")
    disassembly = native_disassemble(pyc_path)
    if disassembly is not None:
        write_disassembly(disassembly, pyasm_path, pyc_path.name)
        return pyasm_path
    if not pycdc:
        raise RuntimeError("pycdc is required to disassemble bytecode from another python version")
    temporary = pyasm_path.with_name(pyasm_path.name + ".raw")
    try:
        pycdc_disassemble(pycdc, str(pyc_path), temporary)
        write_disassembly_from_file(temporary, pyasm_path, pyc_path.name)
    finally:
        temporary.unlink(missing_ok=True)
    return pyasm_path


def process_directory(directory, pycdc, use_cure=True, strict=False):
    directory = Path(directory).resolve()
    pyc_files = sorted(path for path in directory.rglob("*.pyc") if not path.name.endswith("_fixed.pyc"))
    if pyc_files and not pycdc:
        raise RuntimeError("pycdc is required to reconstruct readable source from pyc files")
    results = []
    disassembly_failures = []
    for index, pyc_path in enumerate(pyc_files, 1):
        print(f"[{index}/{len(pyc_files)}] extracting disassembly: {pyc_path.relative_to(directory)}")
        try:
            create_pyasm_from_pyc(pyc_path, pycdc)
        except Exception as exc:
            disassembly_failures.append({"pyc": str(pyc_path), "python": None, "pyasm": None, "errors": [f"disassembly: {exc}"]})
            print_error(f"{pyc_path.name}: {exc}")
    pyasm_files = sorted(directory.rglob("*.pyasm"))
    for index, pyasm_path in enumerate(pyasm_files, 1):
        print(f"[{index}/{len(pyasm_files)}] converting disassembly: {pyasm_path.relative_to(directory)}")
        try:
            result = convert_pyasm(pyasm_path, pyasm_path.with_suffix(".py"), pycdc, use_cure)
            results.append(result)
            print(f"  python: {Path(result['python']).name}")
        except Exception as exc:
            results.append({"pyc": None, "python": None, "pyasm": str(pyasm_path), "errors": [str(exc)]})
            print_error(f"{pyasm_path.name}: {exc}")
    results.extend(disassembly_failures)
    master_path = directory / "all_functions_disasm.txt"
    with master_path.open("w", encoding="utf-8", newline="\n") as master:
        for pyasm_path in sorted(directory.rglob("*.pyasm")):
            master.write("=" * 78 + "\n")
            master.write(f"file: {pyasm_path.relative_to(directory)}\n")
            master.write("=" * 78 + "\n")
            with pyasm_path.open("r", encoding="utf-8", errors="replace") as source:
                shutil.copyfileobj(source, master, length=1024 * 1024)
            master.write("\n\n")
    success = sum(1 for item in results if item.get("python"))
    failures = sum(1 for item in results if item.get("errors"))
    report = {
        "version": version,
        "input_directory": str(directory),
        "python_files_created": success,
        "failed_items": failures,
        "pyc_files_found": len(pyc_files),
        "pyasm_files_found": len(pyasm_files),
        "results": results,
    }
    report_path = directory / "exetopy_report.json"
    write_text_atomic(report_path, json.dumps(report, indent=2, ensure_ascii=False))
    print(f"done: {success} python files, {failures} failed items")
    print(f"report: {report_path}")
    if strict and failures:
        return 4
    return 0 if success or not (pyc_files or pyasm_files) else 4


def process_exe(exe_path, args):
    exe_path = find_executable_file(exe_path)
    if not exe_path:
        raise RuntimeError("file not found")
    pycdc = find_pycdc(args.pycdc, allow_download=not args.no_download)
    extractor = find_pyinstxtractor(args.extractor, allow_download=not args.no_download)
    output_dir = extract_exe(exe_path, extractor, reextract=args.reextract)
    return process_directory(output_dir, pycdc, use_cure=not args.no_cure, strict=args.strict)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="exetopy.py",
        description="extract pyinstaller executables and recover readable python source from bytecode",
    )
    parser.add_argument("input", nargs="?", help="a pyinstaller exe, directory, pyc, or pyasm file")
    parser.add_argument("output", nargs="?", help="output python path for a single pyc or pyasm file")
    parser.add_argument("--pycdc", help="path to a pycdc executable")
    parser.add_argument("--extractor", help="path to a local pyinstxtractor.py script")
    parser.add_argument("--no-download", action="store_true", help="disable automatic tool downloads")
    parser.add_argument("--no-cure", action="store_true", help="disable optional source cleanup")
    parser.add_argument("--reextract", action="store_true", help="replace an existing extraction directory")
    parser.add_argument("--strict", action="store_true", help="return an error when any file fails")
    parser.add_argument("--version", action="version", version=f"exetopy {version}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    input_value = args.input
    if not input_value:
        try:
            input_value = input("enter exe name (without extension): ").strip()
        except EOFError:
            print_error("no input was provided")
            return 2
        if not input_value:
            print_error("no input was provided")
            return 2
    input_path = Path(input_value).expanduser()
    try:
        if input_path.is_dir():
            needs_decompiler = any(input_path.rglob("*.pyc")) or any(
                matching_pyc(item) for item in input_path.rglob("*.pyasm")
            )
            pycdc = find_pycdc(args.pycdc, allow_download=not args.no_download) if needs_decompiler else None
            return process_directory(input_path, pycdc, use_cure=not args.no_cure, strict=args.strict)
        if input_path.suffix.lower() == ".exe" or (not input_path.suffix and find_executable_file(input_value)):
            return process_exe(input_value, args)
        if input_path.suffix.lower() == ".pyasm":
            paired = matching_pyc(input_path)
            if paired is None:
                adjacent = find_adjacent_executable(input_path)
                if adjacent:
                    extractor = find_pyinstxtractor(args.extractor, allow_download=not args.no_download)
                    extracted = extract_exe(adjacent, extractor, reextract=args.reextract)
                    candidates = list(extracted.rglob(f"{input_path.stem}.pyc"))
                    if not candidates:
                        candidates = list(extracted.rglob(f"{input_path.stem}.*.pyc"))
                    if candidates:
                        paired = candidates[0]
                    elif not args.reextract:
                        raise RuntimeError(
                            f"the existing extraction directory has no matching .pyc; rerun with: python3 exetopy.py {adjacent.name} --reextract"
                        )
            pycdc = find_pycdc(args.pycdc, allow_download=not args.no_download) if paired else None
            output_path = Path(args.output).expanduser() if args.output else input_path.with_suffix(".py")
            result = convert_pyasm(input_path, output_path, pycdc, use_cure=not args.no_cure)
            print(f"created: {result['python']}")
            print(f"method: decompiled from matching pyc with pycdc {pycdc_release}")
            return 0
        if input_path.suffix.lower() == ".pyc":
            pycdc = find_pycdc(args.pycdc, allow_download=not args.no_download)
            output_path = Path(args.output).expanduser() if args.output else input_path.with_suffix(".py")
            result = process_pyc(input_path, pycdc, use_cure=not args.no_cure, output_path=output_path)
            for error in result["errors"]:
                print_error(error)
            print(f"created: {result['python'] or 'no python source'}")
            print(f"disassembly: {result['pyasm'] or 'not available'}")
            return 0 if result["python"] else 4
        if not input_path.exists():
            found = find_executable_file(input_value)
            if found:
                return process_exe(found, args)
        print_error("input file was not found or has an unsupported extension")
        return 2
    except KeyboardInterrupt:
        print_error("interrupted")
        return 130
    except Exception as exc:
        print_error(str(exc))
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
