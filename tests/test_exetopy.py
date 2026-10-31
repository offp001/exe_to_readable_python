import ast
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

import exetopy


class parser_tests(unittest.TestCase):
    def test_inline_and_standalone_labels(self):
        source = """# source: sample.pyc
  0             RESUME                   0
  1             LOAD_CONST               1 (None)
  2     L1:     POP_JUMP_IF_FALSE        3 (to L2)
        L2:
  3             RETURN_VALUE
"""
        instructions, ignored, dangling = exetopy.parse_disassembly(source)
        self.assertEqual(
            [entry["opcode"] for entry in instructions],
            ["RESUME", "LOAD_CONST", "POP_JUMP_IF_FALSE", "RETURN_VALUE"],
        )
        self.assertEqual(instructions[2]["labels"], ["L1"])
        self.assertEqual(instructions[3]["labels"], ["L2"])
        self.assertEqual(ignored, [])
        self.assertEqual(dangling, [])

    def test_newer_cpython_opcodes_are_parsed_without_unknown_opcode_lists(self):
        source = """0 BINARY_SLICE
1 CALL_INTRINSIC_1 0
2 CONVERT_VALUE 1
3 LOAD_COMMON_CONSTANT 0
4 LOAD_FAST_BORROW 1 (value)
5 FORMAT_SIMPLE
6 POP_ITER
7 SET_FUNCTION_ATTRIBUTE 1
"""
        instructions, ignored, dangling = exetopy.parse_disassembly(source)
        self.assertEqual(len(instructions), 8)
        self.assertEqual(ignored, [])
        self.assertEqual(dangling, [])
        self.assertEqual(instructions[0]["opcode"], "BINARY_SLICE")
        self.assertEqual(instructions[3]["opcode"], "LOAD_COMMON_CONSTANT")

    def test_code_object_headers_are_not_counted_as_instructions(self):
        source = """Disassembly of <code object sample at 0x123, file \"sample.py\", line 1>:
  0 RESUME 0
  2 LOAD_CONST 0 (None)
  4 RETURN_VALUE
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.pyasm"
            path.write_text(source, encoding="utf-8")
            report = exetopy.scan_disassembly(path)
        self.assertEqual(report["instructions"], 3)
        self.assertEqual(report["format"], "cpython disassembly")
        self.assertEqual(report["ignored_lines"], 0)
        self.assertEqual(report["code_objects_referenced"], 1)

    def test_pyasm_without_pyc_does_not_create_fake_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "sample.pyasm"
            output = Path(temporary) / "sample.py"
            source.write_text("0 RESUME 0\n2 LOAD_CONST 0 (None)\n4 RETURN_VALUE\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                exetopy.convert_pyasm(source, output)
            self.assertFalse(output.exists())

    def test_matching_pyc_is_used_for_source_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            pyc = directory / "sample.pyc"
            pyc.write_bytes(b"placeholder")
            pyasm = directory / "sample.pyasm"
            pyasm.write_text("# source: sample.pyc\n0 RESUME 0\n", encoding="utf-8")
            self.assertEqual(exetopy.matching_pyc(pyasm), pyc.resolve())

    def test_streaming_source_writer_adds_only_source_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = directory / "raw.py"
            output = directory / "result.py"
            raw.write_text("def answer():\n    return 42\n", encoding="utf-8")
            exetopy.write_python_from_file(raw, output, "sample.pyasm")
            generated = output.read_text(encoding="utf-8")
            self.assertTrue(generated.startswith("# source: sample.pyasm\n\n"))
            ast.parse(generated)
            py_compile.compile(str(output), doraise=True)

    def test_every_generated_pyasm_is_converted_and_pyc_is_preserved(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, value in (("first", 11), ("second", 22)):
                source = directory / f"{name}.py"
                source.write_text(f"value = {value}\n", encoding="utf-8")
                py_compile.compile(str(source), cfile=str(directory / f"{name}.pyc"), doraise=True)
            pycdc = directory / "pycdc"
            pycdc.write_text(
                "#!/usr/bin/env python3\n"
                "print('def recovered():\\n    return 17')\n",
                encoding="utf-8",
            )
            pycdc.chmod(0o755)
            status = exetopy.process_directory(directory, str(pycdc))
            self.assertEqual(status, 0)
            for name in ("first", "second"):
                self.assertTrue((directory / f"{name}.pyc").is_file())
                self.assertTrue((directory / f"{name}.pyasm").is_file())
                self.assertTrue((directory / f"{name}.py").is_file())
            report = json.loads((directory / "exetopy_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["pyasm_files_found"], 2)
            self.assertEqual(report["python_files_created"], 2)

    def test_exe_pipeline_preserves_pyc_and_generates_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            exe = directory / "demo.exe"
            exe.write_bytes(b"placeholder")
            pycdc = directory / "pycdc"
            pycdc.write_text(
                "#!/usr/bin/env python3\n"
                "print('def recovered():\\n    return 17')\n",
                encoding="utf-8",
            )
            pycdc.chmod(0o755)
            extractor = directory / "pyinstxtractor.py"
            extractor.write_text(
                "import py_compile\n"
                "import sys\n"
                "from pathlib import Path\n"
                "exe = Path(sys.argv[1])\n"
                "output = Path(str(exe) + '_extracted')\n"
                "output.mkdir()\n"
                "source = output / 'module.py'\n"
                "source.write_text('value = 17\\n', encoding='utf-8')\n"
                "py_compile.compile(str(source), cfile=str(output / 'module.pyc'), doraise=True)\n",
                encoding="utf-8",
            )
            status = exetopy.main([
                str(exe),
                "--pycdc", str(pycdc),
                "--extractor", str(extractor),
            ])
            extracted = Path(str(exe) + "_extracted")
            self.assertEqual(status, 0)
            self.assertTrue((extracted / "module.pyc").is_file())
            self.assertTrue((extracted / "module.pyasm").is_file())
            self.assertTrue((extracted / "module.py").is_file())
            self.assertTrue((extracted / "all_functions_disasm.txt").is_file())
            self.assertTrue((extracted / "exetopy_report.json").is_file())


if __name__ == "__main__":
    unittest.main()
