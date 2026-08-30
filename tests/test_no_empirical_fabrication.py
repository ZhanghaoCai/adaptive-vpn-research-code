"""Guardrails against reintroducing generated observations as research evidence."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (ROOT / "src", ROOT / "scripts", ROOT / "analysis")
FORBIDDEN = {
    "randomly generated QoS observations": re.compile(r"random\.uniform\s*\("),
    "fixed vendor-monitor metric constructors": re.compile(
        r"class\s+(?:Zoom|Teams|Meet)Monitor\b"
    ),
    "placeholder empirical collection": re.compile(
        r"(?:simulate metric collection|simulated metrics for now)", re.IGNORECASE
    ),
    "unimplemented production path switch": re.compile(
        r"TODO:\s*Implement actual VPN switching", re.IGNORECASE
    ),
}


def test_production_code_contains_no_empirical_fabrication_markers():
    failures: list[str] = []
    for root in PRODUCTION_ROOTS:
        for path in sorted(root.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for label, pattern in FORBIDDEN.items():
                if pattern.search(text):
                    failures.append(f"{path.relative_to(ROOT)}: {label}")

    assert failures == [], "\n".join(failures)
