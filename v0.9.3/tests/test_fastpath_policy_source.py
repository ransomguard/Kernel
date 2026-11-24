"""No Windows side effects: compile and exercise the actual pure-C fast path."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class FastPathPolicyTests(unittest.TestCase):
    def test_native_c_rules(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if compiler is None:
            self.skipTest("A C compiler is required for the portable-rule test")
        with tempfile.TemporaryDirectory() as tmp:
            exe = pathlib.Path(tmp) / "fastpath_test"
            compile_result = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                 str(ROOT / "Anti_Ransom_Driver" / "FastPathPolicy.c"),
                 str(ROOT / "tests" / "fastpath_policy_smoke.c"),
                 "-o", str(exe)], text=True, capture_output=True, check=False)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(exe)], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS 29 FastPathPolicy cases", result.stdout)

    def test_project_links_real_classifier(self):
        project = (ROOT / "Anti_Ransom_Driver" / "Anti_Ransom_Driver.vcxproj").read_text()
        monitor = (ROOT / "Anti_Ransom_Driver" / "ProcessMonitor.c").read_text(encoding="utf-8-sig")
        self.assertIn('ClCompile Include="FastPathPolicy.c"', project)
        self.assertIn("RgFastPathEvaluate(", monitor)
        self.assertIn("CreationStatus = STATUS_ACCESS_DENIED", monitor)
        self.assertNotIn("ArwpIsTrustedParent", monitor)


if __name__ == "__main__":
    unittest.main()
