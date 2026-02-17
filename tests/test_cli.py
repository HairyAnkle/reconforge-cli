from pathlib import Path

from reconforge.core import ensure_workspace, run_report, write_lines


def test_workspace_and_report(tmp_path: Path) -> None:
    ensure_workspace(tmp_path)

    write_lines(tmp_path / "subdomains" / "resolved.txt", ["a.example.com", "b.example.com"])
    write_lines(tmp_path / "alive" / "alive.txt", ["https://a.example.com"])
    write_lines(tmp_path / "ports" / "services.txt", ["a.example.com:443"])

    report = run_report(tmp_path)
    content = report.read_text(encoding="utf-8")

    assert "Resolved subdomains: **2**" in content
    assert "Live web endpoints: **1**" in content
    assert "Open service entries: **1**" in content
