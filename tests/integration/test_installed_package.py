import subprocess
import sys


def test_installed_environment_exposes_analysis_package_outside_repository(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-c", "import analysis.statistical_analysis"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
