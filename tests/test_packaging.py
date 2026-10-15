import importlib.util
from pathlib import Path, PurePosixPath
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("atlas_installer", ROOT / "packaging" / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class PackagingTests(unittest.TestCase):
    def test_demo_fixtures_are_exact_synthetic_copies(self):
        for name in ("nmap.xml", "device.json", "scan.nessus", "nuclei.jsonl", "httpx.jsonl", "manual.json"):
            with self.subTest(name=name):
                self.assertEqual((ROOT / "fixtures" / name).read_bytes(), (ROOT / "atlas" / "demo_fixtures" / name).read_bytes())

    def test_core_install_has_no_optional_engine_dependency(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(config["project"]["dependencies"], [])
        self.assertEqual(config["project"]["gui-scripts"]["assessment-atlas"], "atlas.desktop:main")
        self.assertIn("desktop-qt", config["project"]["optional-dependencies"])

    def test_desktop_shortcut_quotes_paths_without_shell_interpretation(self):
        value = installer.desktop_entry(PurePosixPath('/home/test user/$data/100%/bin/assessment-atlas'), PurePosixPath('/home/test user/atlas.svg'))
        self.assertIn('Exec="/home/test user/\\\\$data/100%%/bin/assessment-atlas"\n', value)
        self.assertIn('Terminal=false\n', value)
        self.assertNotIn('/bin/sh', value)

    def test_core_only_shortcut_keeps_a_terminal_for_shutdown(self):
        value = installer.desktop_entry(PurePosixPath('/home/user/bin/atlas-desktop'), PurePosixPath('/home/user/icon.svg'), browser=True)
        self.assertIn('Exec="/home/user/bin/atlas-desktop" --browser\n', value)
        self.assertIn('Terminal=true\n', value)


if __name__ == "__main__":
    unittest.main()
