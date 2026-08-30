import os
import re
import subprocess
from pathlib import Path

import pytest

from adaptive_vpn.lab import WireGuardLab


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.private_key_count = 0

    def __call__(self, command, **kwargs):
        argv = tuple(str(part) for part in command)
        self.commands.append(argv)
        if argv == ("wg", "genkey"):
            self.private_key_count += 1
            stdout = f"private-key-{self.private_key_count}\n"
        elif argv == ("wg", "pubkey"):
            stdout = f"public-{kwargs['input'].strip()}\n"
        else:
            stdout = " ".join(argv) + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout, "")


class ResidueRunner(RecordingRunner):
    def __call__(self, command, **kwargs):
        result = super().__call__(command, **kwargs)
        argv = tuple(str(part) for part in command)
        if argv == ("ip", "netns", "list"):
            return subprocess.CompletedProcess(argv, 0, "avpn-client\n", "")
        return result


def make_lab(tmp_path: Path, runner: RecordingRunner) -> WireGuardLab:
    return WireGuardLab(runner=runner, runtime_dir=tmp_path / "avpn-runtime")


def test_setup_uses_only_bounded_resource_names_and_argument_arrays(tmp_path):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)

    lab.setup()

    allowed_name = re.compile(r"avpn-(?:client|server|[cs][abc]|wg[abc])\Z")
    assert runner.commands
    assert all(isinstance(command, tuple) for command in runner.commands)
    resource_names = {
        token
        for command in runner.commands
        for token in command
        if token.startswith("avpn-")
    }
    assert resource_names
    assert all(allowed_name.fullmatch(name) for name in resource_names)

    command_text = "\n".join(" ".join(command) for command in runner.commands)
    assert "iptables -F" not in command_text
    assert "nft flush ruleset" not in command_text
    assert " default " not in f" {command_text} "
    assert os.stat(lab.runtime_dir).st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in lab.key_files)


def test_cleanup_rejects_non_prefixed_namespace_without_running_commands(tmp_path):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)

    with pytest.raises(ValueError, match="avpn-"):
        lab.cleanup(namespaces=("client",))

    assert runner.commands == []


def test_cleanup_never_recursively_deletes_unowned_runtime_content(tmp_path):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)
    lab.runtime_dir.mkdir(mode=0o700)
    for key_file in lab.key_files:
        key_file.write_text("owned-key\n", encoding="ascii")
    unrelated = lab.runtime_dir / "keep-me.txt"
    unrelated.write_text("not owned by the lab\n", encoding="ascii")

    lab.cleanup()

    assert unrelated.read_text(encoding="ascii") == "not owned by the lab\n"
    assert all(not key_file.exists() for key_file in lab.key_files)


def test_assert_clean_rejects_owned_namespace_residue_without_deleting_it(tmp_path):
    runner = ResidueRunner()
    lab = make_lab(tmp_path, runner)

    with pytest.raises(RuntimeError, match="not clean"):
        lab.assert_clean()

    assert not any("delete" in command for command in runner.commands)


def test_impair_applies_half_rtt_to_each_end_of_only_one_path(tmp_path):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)

    lab.impair("a", rtt_ms=80.0, jitter_ms=10.0, loss_pct=1.0)

    assert len(runner.commands) == 2
    assert runner.commands[0][:8] == (
        "ip",
        "netns",
        "exec",
        "avpn-client",
        "tc",
        "qdisc",
        "replace",
        "dev",
    )
    assert runner.commands[1][:8] == (
        "ip",
        "netns",
        "exec",
        "avpn-server",
        "tc",
        "qdisc",
        "replace",
        "dev",
    )
    assert "avpn-ca" in runner.commands[0]
    assert "avpn-sa" in runner.commands[1]
    assert all("40ms" in command and "5ms" in command for command in runner.commands)
    assert all("avpn-cb" not in command and "avpn-cc" not in command for command in runner.commands)


def test_impair_accepts_registered_path_and_netem_field_names(tmp_path):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)

    lab.impair(
        "path-a",
        delay_ms=80,
        jitter_ms=10,
        loss_pct=8,
        loss_correlation_pct=70,
        rate_mbit=10,
    )

    assert len(runner.commands) == 2
    for command in runner.commands:
        command_text = " ".join(command)
        assert "delay 40ms 5ms" in command_text
        assert "loss" in command_text and "70%" in command_text
        assert "rate 10mbit" in command_text


def test_status_captures_links_routes_qdiscs_and_wireguard_for_both_namespaces(
    tmp_path,
):
    runner = RecordingRunner()
    lab = make_lab(tmp_path, runner)

    status = lab.status()

    assert set(status) == {"avpn-client", "avpn-server"}
    assert all(
        set(namespace_status) == {"links", "routes", "qdiscs", "wireguard"}
        for namespace_status in status.values()
    )
    assert len(runner.commands) == 8
    assert all(command[:3] == ("ip", "netns", "exec") for command in runner.commands)
