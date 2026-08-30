"""Atomic, versioned, and hash-verifiable experiment evidence bundles."""

from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import heapq
import io
import json
import math
import os
import re
import stat
import uuid
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, TextIO

from adaptive_vpn.provenance import ensure_no_secrets, sha256_file

PACKET_FIELDS = (
    "sequence",
    "path_id",
    "sent_ns",
    "received_ns",
    "status",
    "rtt_ms",
    "datagram_bytes",
)
LEGACY_EVIDENCE_SCHEMA_VERSION = "1.0.0"
STRICT_PACKET_EVENT_SCHEMA_VERSION = "1.1.0"
CURRENT_MANIFEST_SCHEMA_VERSION = "1.2.0"
# Kept as the public legacy-writer alias until the atomic workflow migration.
EVIDENCE_SCHEMA_VERSION = STRICT_PACKET_EVENT_SCHEMA_VERSION
UINT64_MAX = (1 << 64) - 1
MAX_DATAGRAM_BYTES = 65_507
_MAX_SCHEDULE_SEED = (1 << 63) - 1
MAX_JSON_BYTES = 1_048_576
MAX_VALIDATION_ERRORS = 100
MAX_VALIDATION_DIAGNOSTIC_CHARACTERS = 1_024
MAX_BUNDLE_ENTRIES = 1_024
MAX_DATASET_BUNDLES = 20_000
MAX_EVIDENCE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BUNDLE_BYTES = 256 * 1024 * 1024
_MAX_JSON_BYTES = MAX_JSON_BYTES
_MAX_INVENTORY_BYTES = 1_048_576
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10_000
_STRATEGIES = {"static", "threshold", "adaptive"}


@dataclass(frozen=True, slots=True)
class ManifestContract:
    """Validation and identity capabilities for one manifest version."""

    writable: bool
    strict_packet_event: bool
    canonical_lf: bool
    registered_identity: bool
    attempt_identity: bool


MANIFEST_CONTRACTS = {
    LEGACY_EVIDENCE_SCHEMA_VERSION: ManifestContract(
        writable=False,
        strict_packet_event=False,
        canonical_lf=False,
        registered_identity=False,
        attempt_identity=False,
    ),
    STRICT_PACKET_EVENT_SCHEMA_VERSION: ManifestContract(
        writable=True,
        strict_packet_event=True,
        canonical_lf=True,
        registered_identity=True,
        attempt_identity=False,
    ),
    CURRENT_MANIFEST_SCHEMA_VERSION: ManifestContract(
        writable=True,
        strict_packet_event=True,
        canonical_lf=True,
        registered_identity=True,
        attempt_identity=True,
    ),
}
READABLE_MANIFEST_SCHEMA_VERSIONS = frozenset(MANIFEST_CONTRACTS)
WRITABLE_MANIFEST_SCHEMA_VERSIONS = frozenset(
    {EVIDENCE_SCHEMA_VERSION, CURRENT_MANIFEST_SCHEMA_VERSION}
)

_V10_MANIFEST_FIELDS = {
    "schema_version",
    "run_id",
    "dataset_id",
    "strategy",
    "scenario",
    "traffic_profile",
    "block",
    "schedule_seed",
}
_REGISTERED_IDENTITY_FIELDS = {
    "ordinal",
    "config_sha256",
    "experimental_unit",
}
_PROVENANCE_FIELDS = {"provenance"}
_V11_MANIFEST_FIELDS = _V10_MANIFEST_FIELDS | _REGISTERED_IDENTITY_FIELDS | _PROVENANCE_FIELDS
_V12_MANIFEST_FIELDS = {
    "schema_version",
    "cell_id",
    "attempt_id",
    "attempt_number",
    "supersedes_attempt_id",
    "campaign_stage",
    "schedule_sha256",
    "dataset_id",
    "strategy",
    "scenario",
    "traffic_profile",
    "block",
    "schedule_seed",
    "ordinal",
    "config_sha256",
    "experimental_unit",
    "provenance",
    "status",
    "failure_reason",
    "finalised_at_utc",
    "evidence_sha256",
}
_MANIFEST_FIELDS_BY_VERSION = {
    LEGACY_EVIDENCE_SCHEMA_VERSION: _V10_MANIFEST_FIELDS,
    STRICT_PACKET_EVENT_SCHEMA_VERSION: _V11_MANIFEST_FIELDS,
    CURRENT_MANIFEST_SCHEMA_VERSION: _V12_MANIFEST_FIELDS,
}
# Compatibility names retained for local callers that used the old constants.
_BASE_MANIFEST_FIELDS = _V10_MANIFEST_FIELDS
_REQUIRED_MANIFEST_FIELDS = _V11_MANIFEST_FIELDS
_RESERVED_ARTIFACTS = {"manifest.json", "SHA256SUMS", "packets.csv", "events.jsonl"}
_CORE_ARTIFACTS = {"manifest.json", "packets.csv", "events.jsonl"}
_FINAL_MANIFEST_FIELDS = {"status", "failure_reason", "finalised_at_utc", "evidence_sha256"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_MIN_DATAGRAM_BYTES = 32
_VALIDATION_TRUNCATION_MESSAGE = (
    "validation diagnostic limit reached; additional errors omitted"
)
_DIAGNOSTIC_CHARACTER_TRUNCATION_SUFFIX = "... [diagnostic truncated]"
_MAX_DIAGNOSTIC_NAMES = 8
RENAME_NOREPLACE = 1
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_LIST_DIRECTORY = 0x00000001
_FILE_READ_ATTRIBUTES = 0x00000080
_DELETE_ACCESS = 0x00010000
_SYNCHRONIZE_ACCESS = 0x00100000
_FILE_SHARE_ALL = 0x00000007
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_RENAME_INFORMATION = 10
_FILE_RENAME_INFORMATION_EX = 65


class DirectoryPublishUnsupportedError(OSError):
    """The filesystem cannot prove an atomic no-replace directory move."""


def _truncate_validation_diagnostic(message: object) -> str:
    text = str(message)
    if len(text) <= MAX_VALIDATION_DIAGNOSTIC_CHARACTERS:
        return text
    prefix_length = (
        MAX_VALIDATION_DIAGNOSTIC_CHARACTERS
        - len(_DIAGNOSTIC_CHARACTER_TRUNCATION_SUFFIX)
    )
    return text[:prefix_length] + _DIAGNOSTIC_CHARACTER_TRUNCATION_SUFFIX


def _format_diagnostic_names(names: Collection[str]) -> str:
    sample = heapq.nsmallest(_MAX_DIAGNOSTIC_NAMES, names)
    omitted = len(names) - len(sample)
    if omitted:
        return f"{sample!r} (+{omitted} additional names omitted)"
    return repr(sample)


def format_validation_diagnostics(
    messages: Iterable[str], *, prefix: str = ""
) -> str:
    """Render public validation failures without re-amplifying diagnostics."""

    rendered = _truncate_validation_diagnostic(prefix)
    if len(rendered) >= MAX_VALIDATION_DIAGNOSTIC_CHARACTERS:
        return rendered
    for message in messages:
        bounded_message = _truncate_validation_diagnostic(message)
        separator = "" if not rendered or rendered.endswith((" ", "\n")) else "; "
        candidate = rendered + separator + bounded_message
        if len(candidate) > MAX_VALIDATION_DIAGNOSTIC_CHARACTERS:
            return _truncate_validation_diagnostic(candidate)
        rendered = candidate
    return rendered


def _bounded_sorted_directory_entries(path: Path) -> tuple[Path, ...]:
    entries: list[Path] = []
    for candidate in path.iterdir():
        entries.append(candidate)
        if len(entries) > MAX_BUNDLE_ENTRIES:
            raise ValueError(
                f"evidence bundle has more than {MAX_BUNDLE_ENTRIES} entries"
            )
    return tuple(sorted(entries, key=lambda candidate: candidate.name))


class _BoundedDiagnostics(list[str]):
    """Collect a fixed number of diagnostics at untrusted artifact boundaries."""

    __slots__ = ("_truncated",)

    def __init__(self) -> None:
        super().__init__()
        self._truncated = False

    @property
    def truncated(self) -> bool:
        return self._truncated

    def append(self, message: str) -> None:
        if self._truncated:
            return
        if len(self) < MAX_VALIDATION_ERRORS:
            super().append(_truncate_validation_diagnostic(message))
            return
        self[-1] = _VALIDATION_TRUNCATION_MESSAGE
        self._truncated = True

    def extend(self, messages: Iterable[str]) -> None:
        for message in messages:
            self.append(message)
            if self._truncated:
                break


def _utc_now() -> str:
    return (
        datetime.now(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _write_text_synced(
    path: Path, content: str, *, encoding: str
) -> None:
    with path.open("w", encoding=encoding, newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_file(path: Path) -> None:
    # Windows FlushFileBuffers requires a handle with write access.
    with path.open("rb+") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        _fsync_directory_windows(path)
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory_windows(path: Path) -> None:
    # FlushFileBuffers requires GENERIC_WRITE and is not a documented directory
    # flush primitive. File contents are fsynced separately; publication uses
    # MoveFileExW(MOVEFILE_WRITE_THROUGH) for the Windows metadata boundary.
    observed = os.lstat(path)
    if not _is_real_directory_stat(observed):
        raise ValueError("directory durability target must be a real directory")


def _is_reparse_point(observed: os.stat_result) -> bool:
    return bool(
        getattr(observed, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _is_real_directory_stat(observed: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and not _is_reparse_point(observed)
    )


def _is_regular_file_stat(observed: os.stat_result) -> bool:
    return (
        stat.S_ISREG(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and not _is_reparse_point(observed)
    )


DirectoryIdentity = tuple[int, int, int, int]


def _directory_identity(observed: os.stat_result) -> DirectoryIdentity:
    return (
        observed.st_dev,
        observed.st_ino,
        stat.S_IFMT(observed.st_mode),
        getattr(observed, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT,
    )


@dataclass(frozen=True, slots=True)
class _DirectoryPublishState:
    source: Path
    destination: Path
    source_parent: Path
    destination_parent: Path
    source_identity: DirectoryIdentity
    source_parent_identity: DirectoryIdentity
    destination_parent_identity: DirectoryIdentity


def _publish_parent_stat(path: Path, *, label: str) -> os.stat_result:
    try:
        observed = os.lstat(path)
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {error}") from error
    if not _is_real_directory_stat(observed):
        raise ValueError(f"{label} must be a real directory")
    if observed.st_ino == 0:
        raise DirectoryPublishUnsupportedError(
            errno.ENOTSUP, f"{label} has no stable filesystem identity"
        )
    return observed


def _validate_directory_publish_paths(
    source: Path, destination: Path
) -> _DirectoryPublishState:
    source = Path(source)
    destination = Path(destination)
    if not _is_safe_basename(source.name) or not _is_safe_basename(destination.name):
        raise ValueError("directory publication names must be safe basenames")
    source_parent = source.parent
    destination_parent = destination.parent
    (
        source_parent,
        destination_parent,
        source_parent_identity,
        destination_parent_identity,
    ) = _validate_publish_parents(
        source_parent, destination_parent
    )
    try:
        source_stat = os.lstat(source)
    except OSError as error:
        raise ValueError(f"staging directory is unavailable: {error}") from error
    if not _is_real_directory_stat(source_stat):
        raise ValueError("staging publication source must be a real directory")
    if source_stat.st_ino == 0:
        raise DirectoryPublishUnsupportedError(
            errno.ENOTSUP, "staging source has no stable filesystem identity"
        )
    return _DirectoryPublishState(
        source=source,
        destination=destination,
        source_parent=source_parent,
        destination_parent=destination_parent,
        source_identity=_directory_identity(source_stat),
        source_parent_identity=source_parent_identity,
        destination_parent_identity=destination_parent_identity,
    )


def _validate_publish_parents(
    source_parent: Path, destination_parent: Path
) -> tuple[Path, Path, DirectoryIdentity, DirectoryIdentity]:
    source_parent_stat = _publish_parent_stat(source_parent, label="staging parent")
    destination_parent_stat = _publish_parent_stat(
        destination_parent, label="final parent"
    )
    if source_parent_stat.st_dev != destination_parent_stat.st_dev:
        raise OSError(errno.EXDEV, "directory publication crosses filesystems")
    return (
        source_parent,
        destination_parent,
        _directory_identity(source_parent_stat),
        _directory_identity(destination_parent_stat),
    )


def _open_publish_parent(path: Path, expected_identity: DirectoryIdentity) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if (
            not _is_real_directory_stat(observed)
            or _directory_identity(observed) != expected_identity
        ):
            raise ValueError("directory publication parent identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _load_renameat2() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as error:
        raise DirectoryPublishUnsupportedError(
            errno.ENOTSUP, "libc does not export renameat2"
        ) from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    return renameat2


def _invoke_renameat2(
    operation: Any,
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
) -> None:
    try:
        result = operation(
            source_fd,
            os.fsencode(source_name),
            destination_fd,
            os.fsencode(destination_name),
            RENAME_NOREPLACE,
        )
    except OSError as error:
        publish_error = error
    else:
        if result == 0:
            return
        error_number = ctypes.get_errno()
        publish_error = OSError(
            error_number,
            os.strerror(error_number) if error_number else "renameat2 failed",
        )
    if publish_error.errno == errno.EEXIST:
        raise FileExistsError(
            errno.EEXIST, "directory publication destination already exists"
        ) from publish_error
    if publish_error.errno == errno.EXDEV:
        raise OSError(
            errno.EXDEV, "directory publication crosses filesystems"
        ) from publish_error
    if publish_error.errno in {
        errno.ENOSYS,
        errno.EINVAL,
        errno.EOPNOTSUPP,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
    }:
        raise DirectoryPublishUnsupportedError(
            publish_error.errno,
            "filesystem does not support renameat2(RENAME_NOREPLACE)",
        ) from publish_error
    raise publish_error


def _rename_directory_linux(
    source: Path, destination: Path, *, renameat2: Any | None = None
) -> None:
    state = _validate_directory_publish_paths(source, destination)
    source_fd = _open_publish_parent(
        state.source_parent, state.source_parent_identity
    )
    try:
        destination_fd = _open_publish_parent(
            state.destination_parent, state.destination_parent_identity
        )
    except BaseException:
        os.close(source_fd)
        raise
    try:
        operation = renameat2 or _load_renameat2()
        _rename_directory_linux_open(
            state,
            source_fd,
            destination_fd,
            operation,
        )
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _verify_publish_parent_paths(state: _DirectoryPublishState) -> None:
    source_parent = _publish_parent_stat(
        state.source_parent, label="staging parent"
    )
    destination_parent = _publish_parent_stat(
        state.destination_parent, label="final parent"
    )
    if (
        _directory_identity(source_parent) != state.source_parent_identity
        or _directory_identity(destination_parent)
        != state.destination_parent_identity
    ):
        raise RuntimeError("directory publication parent identity changed")


def _verify_linux_moved_directory(
    state: _DirectoryPublishState,
    destination_fd: int,
) -> None:
    moved = os.stat(
        state.destination.name,
        dir_fd=destination_fd,
        follow_symlinks=False,
    )
    if (
        not _is_real_directory_stat(moved)
        or _directory_identity(moved) != state.source_identity
    ):
        raise RuntimeError("published directory identity does not match source")


def _rollback_directory_linux_open(
    state: _DirectoryPublishState,
    source_fd: int,
    destination_fd: int,
    operation: Any,
) -> None:
    _invoke_renameat2(
        operation,
        destination_fd,
        state.destination.name,
        source_fd,
        state.source.name,
    )
    restored = os.stat(
        state.source.name,
        dir_fd=source_fd,
        follow_symlinks=False,
    )
    if (
        not _is_real_directory_stat(restored)
        or _directory_identity(restored) != state.source_identity
    ):
        raise RuntimeError("rolled-back directory identity does not match source")


def _rename_directory_linux_open(
    state: _DirectoryPublishState,
    source_fd: int,
    destination_fd: int,
    operation: Any,
) -> None:
    source_now = os.stat(
        state.source.name, dir_fd=source_fd, follow_symlinks=False
    )
    if (
        not _is_real_directory_stat(source_now)
        or _directory_identity(source_now) != state.source_identity
    ):
        raise ValueError("staging publication source identity changed")
    _invoke_renameat2(
        operation,
        source_fd,
        state.source.name,
        destination_fd,
        state.destination.name,
    )
    try:
        _verify_linux_moved_directory(state, destination_fd)
    except BaseException as verification_error:
        try:
            _rollback_directory_linux_open(
                state,
                source_fd,
                destination_fd,
                operation,
            )
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both
            raise BaseExceptionGroup(
                "directory identity verification and rollback failures",
                [verification_error, rollback_error],
            ) from verification_error
        raise


def _publish_directory_linux(
    source: Path,
    destination: Path,
    *,
    renameat2: Any | None = None,
    fsync_directory: Any | None = None,
) -> None:
    sync_directory = fsync_directory or _fsync_directory
    state = _validate_directory_publish_paths(source, destination)
    source_fd = _open_publish_parent(
        state.source_parent, state.source_parent_identity
    )
    try:
        destination_fd = _open_publish_parent(
            state.destination_parent, state.destination_parent_identity
        )
    except BaseException:
        os.close(source_fd)
        raise
    moved = False
    try:
        operation = renameat2 or _load_renameat2()
        _rename_directory_linux_open(
            state,
            source_fd,
            destination_fd,
            operation,
        )
        moved = True
        os.fsync(source_fd)
        os.fsync(destination_fd)
        sync_directory(state.source_parent)
        _verify_publish_parent_paths(state)
        sync_directory(state.destination_parent)
        _verify_publish_parent_paths(state)
        _verify_linux_moved_directory(state, destination_fd)
    except BaseException as publish_error:
        if not moved:
            raise
        try:
            _rollback_directory_linux_open(
                state,
                source_fd,
                destination_fd,
                operation,
            )
            os.fsync(source_fd)
            os.fsync(destination_fd)
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both failures
            raise BaseExceptionGroup(
                "directory publication and rollback failures",
                [publish_error, rollback_error],
            ) from publish_error
        raise
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _windows_extended_path(path: Path) -> str:
    absolute = os.path.abspath(os.fspath(path))
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute.lstrip("\\")
    return "\\\\?\\" + absolute


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", ctypes.c_uint32),
        ("creation_time_low", ctypes.c_uint32),
        ("creation_time_high", ctypes.c_uint32),
        ("access_time_low", ctypes.c_uint32),
        ("access_time_high", ctypes.c_uint32),
        ("write_time_low", ctypes.c_uint32),
        ("write_time_high", ctypes.c_uint32),
        ("volume_serial_number", ctypes.c_uint32),
        ("file_size_high", ctypes.c_uint32),
        ("file_size_low", ctypes.c_uint32),
        ("number_of_links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _WindowsFileRenameInfoEx(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_uint16 * 1),
    ]


WindowsHandleIdentity = tuple[int, int, int]


def _open_directory_handle_windows(
    path: Path,
    *,
    rename_source: bool,
) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    access = _FILE_READ_ATTRIBUTES | _SYNCHRONIZE_ACCESS
    flags = _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT
    if rename_source:
        access |= _DELETE_ACCESS
        flags |= _FILE_FLAG_WRITE_THROUGH
    else:
        access |= _FILE_LIST_DIRECTORY
    handle = create_file(
        _windows_extended_path(path),
        access,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, invalid_handle}:
        error_number = ctypes.get_last_error()
        raise OSError(error_number, f"cannot open directory handle for {path.name}")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        error_number = ctypes.get_last_error()
        raise OSError(error_number, "CloseHandle failed")


def _windows_handle_identity(handle: int) -> WindowsHandleIdentity:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsByHandleFileInformation),
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsByHandleFileInformation()
    if not get_information(ctypes.c_void_p(handle), ctypes.byref(information)):
        error_number = ctypes.get_last_error()
        raise OSError(error_number, "GetFileInformationByHandle failed")
    file_index = (information.file_index_high << 32) | information.file_index_low
    return (
        information.volume_serial_number,
        file_index,
        information.file_attributes,
    )


def _require_windows_handle_identity(
    handle: int,
    expected: DirectoryIdentity,
    *,
    label: str,
) -> WindowsHandleIdentity:
    identity = _windows_handle_identity(handle)
    _volume, file_index, attributes = identity
    if (
        file_index != expected[1]
        or not attributes & _FILE_ATTRIBUTE_DIRECTORY
        or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} handle identity changed")
    return identity


def _invoke_set_file_information_rename_windows(
    source_handle: int,
    destination_parent_handle: int,
    destination_name: str,
) -> None:
    encoded_name = destination_name.encode("utf-16-le")
    name_offset = _WindowsFileRenameInfoEx.file_name.offset
    # FILE_RENAME_INFO declares FileName[1]; include its trailing WCHAR even
    # though FileNameLength deliberately excludes that terminator.
    buffer_size = name_offset + len(encoded_name) + ctypes.sizeof(ctypes.c_uint16)
    buffer = ctypes.create_string_buffer(buffer_size)
    information = ctypes.cast(
        buffer, ctypes.POINTER(_WindowsFileRenameInfoEx)
    ).contents
    information.flags = 0
    information.root_directory = destination_parent_handle
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + name_offset,
        encoded_name,
        len(encoded_name),
    )
    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("status", ctypes.c_void_p),
            ("information", ctypes.c_void_p),
        ]

    ntdll = ctypes.WinDLL("ntdll")
    set_information = ntdll.NtSetInformationFile
    set_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    set_information.restype = ctypes.c_long
    status_to_error = ntdll.RtlNtStatusToDosError
    status_to_error.argtypes = [ctypes.c_long]
    status_to_error.restype = ctypes.c_uint32
    for information_class in (
        _FILE_RENAME_INFORMATION_EX,
        _FILE_RENAME_INFORMATION,
    ):
        io_status = _IoStatusBlock()
        status = set_information(
            ctypes.c_void_p(source_handle),
            ctypes.byref(io_status),
            buffer,
            buffer_size,
            information_class,
        )
        if status >= 0:
            return
        error_number = int(status_to_error(status))
        if information_class == _FILE_RENAME_INFORMATION_EX and error_number in {
            1,
            50,
            87,
            120,
        }:
            continue
        raise _publish_directory_windows_error(
            OSError(error_number, "NtSetInformationFile rename failed")
        )
    raise DirectoryPublishUnsupportedError(
        errno.ENOTSUP,
        "Windows filesystem does not support handle-bound directory rename",
    )


def _move_file_ex_windows(source: Path, destination: Path, flags: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file_ex = kernel32.MoveFileExW
    move_file_ex.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move_file_ex.restype = ctypes.c_int
    return bool(
        move_file_ex(
            _windows_extended_path(source),
            _windows_extended_path(destination),
            flags,
        )
    )


def _publish_directory_windows_error(error: OSError) -> OSError:
    error_number = getattr(error, "winerror", None) or error.errno
    if isinstance(error, FileExistsError) or error_number in {80, 183}:
        return FileExistsError(183, "directory publication destination already exists")
    if error_number in {17, errno.EXDEV}:
        return OSError(errno.EXDEV, "directory publication crosses volumes")
    if error_number in {1, 50, 87, 120}:
        return DirectoryPublishUnsupportedError(
            error_number, "Windows does not support no-replace directory publication"
        )
    return error


def _invoke_move_file_ex(
    operation: Any, source: Path, destination: Path
) -> None:
    try:
        result = operation(source, destination, _MOVEFILE_WRITE_THROUGH)
    except OSError as error:
        raise _publish_directory_windows_error(error) from error
    if not result:
        error_number = ctypes.get_last_error()
        raise _publish_directory_windows_error(
            OSError(error_number, "MoveFileExW failed")
        )


def _verify_directory_publish_result(state: _DirectoryPublishState) -> None:
    try:
        source_after = os.lstat(state.source)
    except FileNotFoundError:
        source_after = None
    if source_after is not None:
        raise RuntimeError("published directory source still exists")
    destination_after = os.lstat(state.destination)
    if (
        not _is_real_directory_stat(destination_after)
        or _directory_identity(destination_after) != state.source_identity
    ):
        raise RuntimeError("published directory identity does not match source")
    source_parent_after = _publish_parent_stat(
        state.source_parent, label="staging parent"
    )
    destination_parent_after = _publish_parent_stat(
        state.destination_parent, label="final parent"
    )
    if (
        _directory_identity(source_parent_after) != state.source_parent_identity
        or _directory_identity(destination_parent_after)
        != state.destination_parent_identity
    ):
        raise RuntimeError("directory publication parent identity changed")


@dataclass(frozen=True, slots=True)
class _WindowsPublishHandles:
    source: int
    source_parent: int
    destination_parent: int
    source_identity: WindowsHandleIdentity
    source_parent_identity: WindowsHandleIdentity
    destination_parent_identity: WindowsHandleIdentity


def _open_windows_publish_handles(
    state: _DirectoryPublishState,
) -> _WindowsPublishHandles:
    opened: list[int] = []
    try:
        source_parent = _open_directory_handle_windows(
            state.source_parent,
            rename_source=False,
        )
        opened.append(source_parent)
        destination_parent = _open_directory_handle_windows(
            state.destination_parent,
            rename_source=False,
        )
        opened.append(destination_parent)
        source = _open_directory_handle_windows(
            state.source,
            rename_source=True,
        )
        opened.append(source)
        source_parent_identity = _require_windows_handle_identity(
            source_parent,
            state.source_parent_identity,
            label="staging parent",
        )
        destination_parent_identity = _require_windows_handle_identity(
            destination_parent,
            state.destination_parent_identity,
            label="final parent",
        )
        source_identity = _require_windows_handle_identity(
            source,
            state.source_identity,
            label="staging source",
        )
        if len(
            {
                source_parent_identity[0],
                destination_parent_identity[0],
                source_identity[0],
            }
        ) != 1:
            raise OSError(errno.EXDEV, "directory publication crosses volumes")
        _verify_publish_parent_paths(state)
        source_now = os.lstat(state.source)
        if _directory_identity(source_now) != state.source_identity:
            raise ValueError("staging publication source identity changed")
        return _WindowsPublishHandles(
            source=source,
            source_parent=source_parent,
            destination_parent=destination_parent,
            source_identity=source_identity,
            source_parent_identity=source_parent_identity,
            destination_parent_identity=destination_parent_identity,
        )
    except BaseException:
        for handle in reversed(opened):
            try:
                _close_windows_handle(handle)
            except OSError:
                pass
        raise


def _close_windows_publish_handles(handles: _WindowsPublishHandles) -> None:
    errors: list[BaseException] = []
    for handle in (
        handles.source,
        handles.destination_parent,
        handles.source_parent,
    ):
        try:
            _close_windows_handle(handle)
        except OSError as error:
            errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("Windows publication handle close failures", errors)


def _verify_windows_handle_publish_result(
    state: _DirectoryPublishState,
    handles: _WindowsPublishHandles,
) -> None:
    _verify_publish_parent_paths(state)
    _require_windows_handle_identity(
        handles.source,
        state.source_identity,
        label="published source",
    )
    _require_windows_handle_identity(
        handles.source_parent,
        state.source_parent_identity,
        label="staging parent",
    )
    _require_windows_handle_identity(
        handles.destination_parent,
        state.destination_parent_identity,
        label="final parent",
    )
    try:
        source_after = os.lstat(state.source)
    except FileNotFoundError:
        source_after = None
    if source_after is not None:
        raise RuntimeError("published directory source still exists")
    destination_after = os.lstat(state.destination)
    if (
        not _is_real_directory_stat(destination_after)
        or _directory_identity(destination_after) != state.source_identity
    ):
        raise RuntimeError("published directory identity does not match source")


def _rollback_windows_handle_publish(
    state: _DirectoryPublishState,
    handles: _WindowsPublishHandles,
) -> None:
    _invoke_set_file_information_rename_windows(
        handles.source,
        handles.source_parent,
        state.source.name,
    )
    restored = os.lstat(state.source)
    if (
        not _is_real_directory_stat(restored)
        or _directory_identity(restored) != state.source_identity
    ):
        raise RuntimeError("rolled-back directory identity does not match source")
    if state.destination.exists():
        raise RuntimeError("rolled-back destination still exists")


def _quarantine_windows_handle_publish(
    state: _DirectoryPublishState,
    handles: _WindowsPublishHandles,
) -> None:
    quarantine_name = f".quarantine-{uuid.uuid4().hex}"
    _invoke_set_file_information_rename_windows(
        handles.source,
        handles.destination_parent,
        quarantine_name,
    )
    if state.destination.exists():
        raise RuntimeError("advertised final path remains after quarantine")


def _rename_directory_windows_handle_open(
    state: _DirectoryPublishState,
    handles: _WindowsPublishHandles,
) -> None:
    _verify_publish_parent_paths(state)
    source_now = os.lstat(state.source)
    if _directory_identity(source_now) != state.source_identity:
        raise ValueError("staging publication source identity changed")
    _invoke_set_file_information_rename_windows(
        handles.source,
        handles.destination_parent,
        state.destination.name,
    )
    try:
        _verify_windows_handle_publish_result(state, handles)
    except BaseException as verification_error:
        try:
            _rollback_windows_handle_publish(state, handles)
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both
            errors: list[BaseException] = [verification_error, rollback_error]
            try:
                _quarantine_windows_handle_publish(state, handles)
            except BaseException as quarantine_error:  # noqa: BLE001
                errors.append(quarantine_error)
            raise BaseExceptionGroup(
                "directory identity verification and recovery failures",
                errors,
            ) from verification_error
        raise


def _quarantine_injected_windows_destination(
    state: _DirectoryPublishState,
    operation: Any,
) -> None:
    quarantine = state.destination_parent / f".quarantine-{uuid.uuid4().hex}"
    _invoke_move_file_ex(operation, state.destination, quarantine)
    if state.destination.exists():
        raise RuntimeError("advertised final path remains after quarantine")


def _rename_directory_windows(
    source: Path, destination: Path, *, move_file_ex: Any | None = None
) -> None:
    state = _validate_directory_publish_paths(source, destination)
    if move_file_ex is None:
        handles = _open_windows_publish_handles(state)
        try:
            _rename_directory_windows_handle_open(state, handles)
        finally:
            _close_windows_publish_handles(handles)
        return

    operation = move_file_ex
    _invoke_move_file_ex(operation, state.source, state.destination)
    try:
        _verify_directory_publish_result(state)
    except BaseException as verification_error:
        try:
            _invoke_move_file_ex(operation, state.destination, state.source)
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both
            errors: list[BaseException] = [verification_error, rollback_error]
            try:
                _quarantine_injected_windows_destination(state, operation)
            except BaseException as quarantine_error:  # noqa: BLE001
                errors.append(quarantine_error)
            raise BaseExceptionGroup(
                "directory identity verification and recovery failures", errors
            ) from verification_error
        raise


def _publish_directory_windows(
    source: Path,
    destination: Path,
    *,
    move_file_ex: Any | None = None,
    fsync_directory: Any | None = None,
) -> None:
    sync_directory = fsync_directory or _fsync_directory
    if move_file_ex is not None:
        _rename_directory_windows(source, destination, move_file_ex=move_file_ex)
        try:
            sync_directory(Path(source).parent)
            sync_directory(Path(destination).parent)
        except BaseException as publish_error:
            try:
                _rename_directory_windows(
                    Path(destination), Path(source), move_file_ex=move_file_ex
                )
                sync_directory(Path(source).parent)
                sync_directory(Path(destination).parent)
            except BaseException as rollback_error:  # noqa: BLE001
                raise BaseExceptionGroup(
                    "directory publication and rollback failures",
                    [publish_error, rollback_error],
                ) from publish_error
            raise
        return

    state = _validate_directory_publish_paths(source, destination)
    handles = _open_windows_publish_handles(state)
    moved = False
    try:
        _rename_directory_windows_handle_open(state, handles)
        moved = True
        sync_directory(state.source_parent)
        _verify_publish_parent_paths(state)
        sync_directory(state.destination_parent)
        _verify_windows_handle_publish_result(state, handles)
    except BaseException as publish_error:
        if not moved:
            raise
        try:
            _rollback_windows_handle_publish(state, handles)
        except BaseException as rollback_error:  # noqa: BLE001 - preserve both failures
            errors: list[BaseException] = [publish_error, rollback_error]
            try:
                _quarantine_windows_handle_publish(state, handles)
            except BaseException as quarantine_error:  # noqa: BLE001
                errors.append(quarantine_error)
            raise BaseExceptionGroup(
                "directory publication and recovery failures", errors
            ) from publish_error
        raise
    finally:
        _close_windows_publish_handles(handles)


def _publish_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename one directory without ever replacing the destination."""

    if os.name == "posix":
        _publish_directory_linux(source, destination)
    elif os.name == "nt":
        _publish_directory_windows(source, destination)
    else:
        raise DirectoryPublishUnsupportedError(
            errno.ENOTSUP, f"unsupported platform for directory publication: {os.name}"
        )


def _remove_probe_candidate(candidate: Path) -> None:
    try:
        observed = os.lstat(candidate)
    except FileNotFoundError:
        return
    if _is_reparse_point(observed) and stat.S_ISDIR(observed.st_mode):
        os.rmdir(candidate)
        return
    if stat.S_ISLNK(observed.st_mode) or _is_regular_file_stat(observed):
        candidate.unlink()
        return
    if not _is_real_directory_stat(observed):
        raise ValueError("probe candidate changed to an unsupported file type")
    for child in _bounded_sorted_directory_entries(candidate):
        child_stat = os.lstat(child)
        if stat.S_ISLNK(child_stat.st_mode) or _is_regular_file_stat(child_stat):
            child.unlink()
        elif _is_reparse_point(child_stat) and stat.S_ISDIR(child_stat.st_mode):
            os.rmdir(child)
        else:
            raise ValueError("probe child changed to an unsupported file type")
    candidate.rmdir()


def _probe_directory_publish_capability(
    staging_parent: Path, final_parent: Path
) -> None:
    """Prove no-replace behavior on the exact staging and final parents."""

    staging_parent = Path(staging_parent)
    final_parent = Path(final_parent)
    _validate_publish_parents(staging_parent, final_parent)
    probe_id = uuid.uuid4().hex
    occupied_source = staging_parent / f".probe-source-{probe_id}"
    occupied_destination = final_parent / f".probe-destination-{probe_id}"
    free_source = staging_parent / f".probe-source-free-{probe_id}"
    free_destination = final_parent / f".probe-destination-free-{probe_id}"
    primary_error: BaseException | None = None
    try:
        occupied_source.mkdir()
        occupied_destination.mkdir()
        free_source.mkdir()
        (occupied_source / "sentinel.txt").write_bytes(b"source-sentinel")
        (occupied_destination / "sentinel.txt").write_bytes(
            b"destination-sentinel"
        )
        (free_source / "payload.bin").write_bytes(b"exact-free-payload")
        try:
            _publish_directory_no_replace(occupied_source, occupied_destination)
        except FileExistsError:
            pass
        else:
            raise RuntimeError(
                "directory no-replace capability overwrote an occupied destination"
            )
        if not occupied_source.is_dir() or not occupied_destination.is_dir():
            raise RuntimeError("occupied no-replace probe changed directory state")
        if (occupied_source / "sentinel.txt").read_bytes() != b"source-sentinel":
            raise RuntimeError("occupied no-replace probe changed its source bytes")
        if (occupied_destination / "sentinel.txt").read_bytes() != b"destination-sentinel":
            raise RuntimeError("occupied no-replace probe changed its destination bytes")

        _publish_directory_no_replace(free_source, free_destination)
        if free_source.exists() or not free_destination.is_dir():
            raise RuntimeError("free no-replace probe did not move the source directory")
        if (free_destination / "payload.bin").read_bytes() != b"exact-free-payload":
            raise RuntimeError("free no-replace probe changed payload bytes")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = _BoundedDiagnostics()
        for candidate in (
            occupied_source,
            occupied_destination,
            free_source,
            free_destination,
        ):
            try:
                _remove_probe_candidate(candidate)
            except (OSError, ValueError) as error:
                cleanup_errors.append(f"probe cleanup failed for {candidate.name}: {error}")
        if cleanup_errors:
            diagnostic = format_validation_diagnostics(cleanup_errors)
            if primary_error is not None:
                primary_error.add_note(diagnostic)
            else:
                raise RuntimeError(diagnostic)


FileSnapshot = tuple[int, ...]


def _file_identity(value: os.stat_result) -> FileSnapshot:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        getattr(value, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT,
    )


def _file_snapshot(value: os.stat_result) -> FileSnapshot:
    return _file_identity(value) + (value.st_ctime_ns,)


def _open_regular_file(path: Path, *, label: str) -> tuple[int, FileSnapshot]:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise ValueError(f"{label} cannot be inspected: {error}") from error
    if not _is_regular_file_stat(before):
        raise ValueError(f"{label} is not a regular non-symlink file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{label} cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise ValueError(f"{label} cannot be opened safely: {error}") from error
    identity = _file_identity(before)
    if not _is_regular_file_stat(opened):
        os.close(descriptor)
        raise ValueError(f"{label} changed to a non-regular file before read")
    if identity != _file_identity(opened):
        os.close(descriptor)
        raise ValueError(f"{label} identity or metadata changed before read")
    return descriptor, _file_snapshot(opened)


def _read_bounded_regular_bytes(
    path: Path, *, maximum_bytes: int, label: str
) -> tuple[bytes, FileSnapshot]:
    """Capture one bounded regular file through a held descriptor."""

    descriptor, snapshot = _open_regular_file(path, label=label)
    try:
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - total)
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            after_path = os.lstat(path)
        except OSError as error:
            raise ValueError(f"{label} disappeared during read") from error
        if total > maximum_bytes:
            raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
        if (
            snapshot != _file_snapshot(after_descriptor)
            or snapshot[:-1] != _file_identity(after_path)
            or not _is_regular_file_stat(after_path)
        ):
            raise ValueError(f"{label} identity or metadata changed during read")
        return b"".join(chunks), snapshot
    finally:
        os.close(descriptor)


def _verify_file_snapshots(
    path: Path, snapshots: dict[str, FileSnapshot], errors: list[str]
) -> None:
    for name, expected in snapshots.items():
        candidate = path / name
        try:
            descriptor, observed = _open_regular_file(candidate, label=name)
            os.close(descriptor)
        except (OSError, ValueError) as error:
            errors.append(f"{name} changed after validation: {error}")
            continue
        if observed != expected:
            errors.append(f"{name} identity or metadata changed during validation")


def _is_safe_basename(name: object) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and name not in {".", ".."}
        and "/" not in name
        and "\\" not in name
        and "\x00" not in name
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _load_json_value(text: str) -> Any:
    if len(text.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"JSON document exceeds {_MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except RecursionError as error:
        raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} levels") from error
    _validate_json_shape(value)
    return value


def _load_json_object(text: str) -> dict[str, Any]:
    value = _load_json_value(text)
    if not isinstance(value, dict):
        raise TypeError("JSON value must be an object")
    return value


def _validate_json_shape(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError(f"JSON document exceeds {_MAX_JSON_NODES} nodes")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} levels")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((child, depth + 1) for child in current)


def _require_non_negative_int(
    name: str, value: object, *, maximum: int | None = UINT64_MAX
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or (maximum is not None and value > maximum)
    ):
        if maximum is None:
            raise ValueError(f"{name} must be a non-negative integer")
        raise ValueError(f"{name} must be an integer between 0 and {maximum}")
    return value


def _validate_packet_row(row: dict[str, Any], *, strict: bool = True) -> None:
    missing = set(PACKET_FIELDS) - row.keys()
    extra = row.keys() - set(PACKET_FIELDS)
    if missing or extra:
        raise ValueError(
            f"packet row schema mismatch; missing={sorted(missing)}, extra={sorted(extra)}"
        )

    maximum = UINT64_MAX if strict else None
    _require_non_negative_int("sequence", row["sequence"], maximum=maximum)
    path_id = row["path_id"]
    if not isinstance(path_id, str) or (not path_id.strip() if strict else not path_id):
        raise ValueError("path_id must be a non-empty string")
    sent_ns = _require_non_negative_int("sent_ns", row["sent_ns"], maximum=maximum)
    datagram_bytes = _require_non_negative_int(
        "datagram_bytes",
        row["datagram_bytes"],
        maximum=MAX_DATAGRAM_BYTES if strict else None,
    )
    if datagram_bytes < _MIN_DATAGRAM_BYTES:
        raise ValueError(f"datagram_bytes must be at least {_MIN_DATAGRAM_BYTES}")

    status = row["status"]
    if not isinstance(status, str) or status not in {"received", "timeout"}:
        raise ValueError("status must be received or timeout")
    received_ns = row["received_ns"]
    rtt_ms = row["rtt_ms"]
    if not strict:
        if received_ns is not None:
            _require_non_negative_int(
                "received_ns", received_ns, maximum=None
            )
        if rtt_ms is not None:
            if isinstance(rtt_ms, bool) or not isinstance(rtt_ms, (int, float)):
                raise TypeError("rtt_ms must be a finite non-negative number or null")
            if not math.isfinite(float(rtt_ms)) or rtt_ms < 0:
                raise ValueError("rtt_ms must be a finite non-negative number or null")
        return
    if status == "timeout":
        if received_ns is not None or rtt_ms is not None:
            raise ValueError("timeout rows require empty received_ns and rtt_ms")
        return

    received_ns = _require_non_negative_int("received_ns", received_ns)
    if received_ns < sent_ns:
        raise ValueError("received_ns must not precede sent_ns")
    if isinstance(rtt_ms, bool) or not isinstance(rtt_ms, (int, float)):
        raise TypeError("rtt_ms must be a finite non-negative number")
    rtt_ms = float(rtt_ms)
    if not math.isfinite(rtt_ms) or rtt_ms < 0:
        raise ValueError("rtt_ms must be a finite non-negative number")
    expected_rtt_ms = (received_ns - sent_ns) / 1_000_000
    if rtt_ms != expected_rtt_ms:
        raise ValueError("rtt_ms does not match sent_ns and received_ns")


def _validate_event(event: dict[str, Any], *, strict: bool = True) -> str:
    if not isinstance(event, dict):
        raise TypeError("event must be an object")
    event_name = event.get("event")
    if not isinstance(event_name, str) or (
        not event_name.strip() if strict else not event_name
    ):
        raise ValueError("event must contain a non-empty event name")
    _validate_json_shape(event)
    ensure_no_secrets(event, location="event")
    encoded = json.dumps(event, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if len((encoded + "\n").encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"event exceeds {_MAX_JSON_BYTES} bytes")
    return encoded


def _load_json_line(raw_line: bytes, *, label: str) -> Any:
    if len(raw_line) > _MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_JSON_BYTES} bytes")
    if not raw_line.strip():
        raise ValueError(f"{label} is blank")
    return _load_json_value(raw_line.decode("utf-8"))


def _validate_structured_artifact_content(name: str, content: str) -> None:
    suffix = Path(name).suffix.lower()
    if suffix == ".json":
        value = _load_json_value(content)
        ensure_no_secrets(value, location=name)
    elif suffix == ".jsonl":
        for line_number, raw_line in enumerate(
            io.BytesIO(content.encode("utf-8")), 1
        ):
            value = _load_json_line(
                raw_line, label=f"{name} line {line_number}"
            )
            ensure_no_secrets(value, location=f"{name}[{line_number}]")


def _canonical_uuid_text(value: object, *, version: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        parsed.version == version
        and parsed.variant == uuid.RFC_4122
        and str(parsed) == value
    )


def _manifest_errors(manifest: dict[str, Any], *, require_final: bool) -> list[str]:
    errors = _BoundedDiagnostics()
    schema_version = manifest.get("schema_version")
    try:
        contract = MANIFEST_CONTRACTS.get(schema_version)
    except TypeError:
        contract = None
    if contract is None:
        fields = _V11_MANIFEST_FIELDS
    else:
        fields = _MANIFEST_FIELDS_BY_VERSION[schema_version]
    required = set(fields)
    if contract is not None and contract.attempt_identity and not require_final:
        required.difference_update(_FINAL_MANIFEST_FIELDS)
    if require_final:
        if schema_version == LEGACY_EVIDENCE_SCHEMA_VERSION:
            required.update({"status", "evidence_sha256"})
        else:
            required.update(_FINAL_MANIFEST_FIELDS)
    missing = sorted(required - manifest.keys())
    if missing:
        errors.append(f"manifest missing fields: {missing}")

    if contract is None:
        errors.append(
            "manifest schema_version must be "
            + ", ".join(sorted(READABLE_MANIFEST_SCHEMA_VERSIONS))
        )
    elif contract.attempt_identity:
        extra = set(manifest) - fields
        if extra:
            errors.append(f"manifest has unexpected fields: {sorted(extra)}")

    for field in ("dataset_id", "scenario", "traffic_profile"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"manifest {field} must be a non-empty string")
    strategy = manifest.get("strategy")
    if not isinstance(strategy, str) or strategy not in _STRATEGIES:
        errors.append("manifest strategy must be static, threshold, or adaptive")

    if contract is not None and contract.attempt_identity:
        if not _canonical_uuid_text(manifest.get("cell_id"), version=5):
            errors.append("manifest cell_id must be a canonical RFC UUIDv5")
        if not _canonical_uuid_text(manifest.get("attempt_id"), version=4):
            errors.append("manifest attempt_id must be a canonical RFC UUIDv4")
        attempt_number = manifest.get("attempt_number")
        valid_attempt_number = (
            not isinstance(attempt_number, bool)
            and isinstance(attempt_number, int)
            and attempt_number >= 1
        )
        if not valid_attempt_number:
            errors.append("manifest attempt_number must be a positive strict integer")
        predecessor = manifest.get("supersedes_attempt_id")
        if predecessor is not None and not _canonical_uuid_text(
            predecessor, version=4
        ):
            errors.append(
                "manifest supersedes_attempt_id must be null or a canonical RFC UUIDv4"
            )
        if valid_attempt_number and attempt_number == 1 and predecessor is not None:
            errors.append("manifest attempt 1 must not have a predecessor")
        if valid_attempt_number and attempt_number >= 2 and predecessor is None:
            errors.append("manifest attempts after 1 require a predecessor")
        campaign_stage = manifest.get("campaign_stage")
        if campaign_stage not in {"smoke", "pilot", "main"}:
            errors.append("manifest campaign_stage must be smoke, pilot, or main")
        schedule_sha256 = manifest.get("schedule_sha256")
        if not isinstance(schedule_sha256, str) or not _SHA256_RE.fullmatch(
            schedule_sha256
        ):
            errors.append("manifest schedule_sha256 must be a lowercase SHA-256 digest")
    elif contract is not None:
        run_id = manifest.get("run_id")
        if not _canonical_uuid_text(run_id, version=4) and not _canonical_uuid_text(
            run_id, version=5
        ):
            errors.append("manifest run_id must be a canonical version-4 or version-5 UUID")

    block = manifest.get("block")
    if isinstance(block, bool) or not isinstance(block, int) or block < 1:
        errors.append("manifest block must be a positive integer")
    seed = manifest.get("schedule_seed")
    if (
        isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= _MAX_SCHEDULE_SEED
    ):
        errors.append(
            "manifest schedule_seed must be an integer between 0 and "
            f"{_MAX_SCHEDULE_SEED}"
        )
    if contract is not None and contract.registered_identity:
        ordinal = manifest.get("ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
            errors.append("manifest ordinal must be a positive integer")
        config_sha256 = manifest.get("config_sha256")
        if not isinstance(config_sha256, str) or not _SHA256_RE.fullmatch(
            config_sha256
        ):
            errors.append("manifest config_sha256 must be a lowercase SHA-256 digest")
        if manifest.get("experimental_unit") != "run":
            errors.append("manifest experimental_unit must be run")
        provenance = manifest.get("provenance")
        if not isinstance(provenance, dict):
            errors.append("manifest provenance must be an object")
        else:
            git_commit = provenance.get("git_commit")
            if not isinstance(git_commit, str) or not re.fullmatch(
                r"[0-9a-f]{40}", git_commit
            ):
                errors.append(
                    "manifest provenance git_commit must be a lowercase 40-hex commit"
                )

    if not require_final:
        return errors

    status = manifest.get("status")
    failure_reason = manifest.get("failure_reason")
    if not isinstance(status, str) or status not in {"complete", "incomplete"}:
        errors.append("manifest has invalid status")
    elif contract is not None and contract.strict_packet_event:
        if status == "complete" and failure_reason is not None:
            errors.append("complete manifest cannot have a failure reason")
        elif status == "incomplete" and (
            not isinstance(failure_reason, str) or not failure_reason.strip()
        ):
            errors.append("incomplete manifest requires a failure reason")
    elif failure_reason is not None and not isinstance(failure_reason, str):
        errors.append("legacy manifest failure_reason must be text or null")

    if contract is not None and contract.strict_packet_event:
        finalised_at = manifest.get("finalised_at_utc")
        if not isinstance(finalised_at, str) or not _UTC_TIMESTAMP_RE.fullmatch(
            finalised_at
        ):
            errors.append(
                "manifest finalised_at_utc must use YYYY-MM-DDTHH:MM:SS.ffffffZ"
            )
        else:
            try:
                datetime.strptime(finalised_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=UTC
                )
            except (OverflowError, ValueError):
                errors.append("manifest finalised_at_utc is invalid")
    if not isinstance(manifest.get("evidence_sha256"), dict):
        errors.append("manifest evidence_sha256 must be an object")
    return errors


def _deep_freeze(value: Any) -> Any:
    """Return a recursively immutable representation of parsed JSON data."""

    if isinstance(value, dict):
        return MappingProxyType({key: _deep_freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(child) for child in value)
    if isinstance(value, set):
        return frozenset(_deep_freeze(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(child) for child in value)
    return value


@dataclass(frozen=True, slots=True)
class BundleValidation:
    valid: bool
    errors: tuple[str, ...]
    checked_files: tuple[str, ...]
    manifest: Any = None
    sha256sums_sha256: str | None = None
    # Captured bytes are returned only for a valid bundle.  Consumers that
    # calculate endpoints must parse this snapshot rather than reopening paths
    # after validation, which would reintroduce a replacement race.
    artifacts: Mapping[str, bytes] | None = None

    def __post_init__(self) -> None:
        diagnostics = _BoundedDiagnostics()
        diagnostics.extend(self.errors)
        object.__setattr__(self, "errors", tuple(diagnostics))
        if self.valid:
            if self.manifest is not None:
                object.__setattr__(self, "manifest", _deep_freeze(self.manifest))
            if self.artifacts is not None:
                object.__setattr__(
                    self,
                    "artifacts",
                    MappingProxyType(dict(self.artifacts)),
                )
        else:
            object.__setattr__(self, "manifest", None)
            object.__setattr__(self, "sha256sums_sha256", None)
            object.__setattr__(self, "artifacts", None)


class EvidenceBundle:
    """Write one run in exclusive staging and publish it after validation.

    The process owner is the trusted writer for a bundle's lifetime. A failed
    sealing operation leaves the staging directory quarantined and immutable
    through this object; callers must not reinterpret it as a completed run.
    """

    writer_schema_version = EVIDENCE_SCHEMA_VERSION
    identity_field = "run_id"

    def __init__(self, base_dir: Path, manifest: dict[str, Any]) -> None:
        _validate_json_shape(manifest)
        manifest_errors = _manifest_errors(manifest, require_final=False)
        if manifest.get("schema_version") != self.writer_schema_version:
            manifest_errors.append(
                f"writer requires current schema {self.writer_schema_version}"
            )
        if manifest_errors:
            raise ValueError("; ".join(manifest_errors))
        ensure_no_secrets(manifest)
        bundle_uuid = uuid.UUID(str(manifest[self.identity_field]))

        self.base_dir = Path(base_dir)
        self.manifest = dict(manifest)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if not _is_real_directory_stat(os.lstat(self.base_dir)):
            raise ValueError("evidence base directory must be a real directory")
        staging_parent = self.base_dir / ".staging"
        final_parent = self.base_dir / "raw"
        staging_parent.mkdir(parents=True, exist_ok=True)
        final_parent.mkdir(parents=True, exist_ok=True)
        _probe_directory_publish_capability(staging_parent, final_parent)
        self.staging_path = staging_parent / str(bundle_uuid)
        self.final_path = final_parent / str(bundle_uuid)
        if self.staging_path.exists() or self.final_path.exists():
            raise FileExistsError(f"evidence bundle already exists for {bundle_uuid}")
        self.staging_path.mkdir()
        self._packet_handle = (self.staging_path / "packets.csv").open(
            "w", newline="", encoding="utf-8"
        )
        self._packet_writer = csv.DictWriter(
            self._packet_handle,
            fieldnames=PACKET_FIELDS,
            lineterminator="\n",
        )
        self._packet_writer.writeheader()
        self._event_handle = (self.staging_path / "events.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        )
        self._packet_count = 0
        self._event_count = 0
        self._sequences: set[int] = set()
        self._state = "open"

    @classmethod
    def create(cls, base_dir: Path, manifest: dict[str, Any]) -> EvidenceBundle:
        return cls(base_dir, manifest)

    def _require_open(self) -> None:
        if self._state != "open":
            raise RuntimeError(
                f"evidence bundle is finalised or unavailable (state={self._state})"
            )

    @property
    def lifecycle_state(self) -> str:
        return self._state

    def write_packet(self, row: dict[str, Any]) -> None:
        self._require_open()
        _validate_packet_row(row)
        sequence = row["sequence"]
        if sequence in self._sequences:
            raise ValueError(f"duplicate sequence: {sequence}")
        self._packet_writer.writerow(row)
        self._sequences.add(sequence)
        self._packet_count += 1

    def write_event(self, event: dict[str, Any]) -> None:
        self._require_open()
        encoded = _validate_event(event)
        self._event_handle.write(encoded + "\n")
        self._event_count += 1

    def write_text_artifact(self, name: str, content: str) -> Path:
        self._require_open()
        candidate = Path(name)
        if (
            not _is_safe_basename(name)
            or candidate.is_absolute()
            or candidate.name != name
            or name in _RESERVED_ARTIFACTS
        ):
            raise ValueError("artifact name must be a safe, unreserved basename")
        _validate_structured_artifact_content(name, content)
        destination = self.staging_path / name
        _write_text_synced(destination, content, encoding="utf-8")
        return destination

    @staticmethod
    def _sync_and_close(handle: TextIO) -> list[Exception]:
        errors: list[Exception] = []
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as error:  # noqa: BLE001 - close must follow any stream failure
            errors.append(error)
        finally:
            try:
                handle.close()
            except Exception as error:  # noqa: BLE001 - preserve secondary close failure
                errors.append(error)
        return errors

    def _seal_streams(self) -> None:
        errors = self._sync_and_close(self._packet_handle)
        errors.extend(self._sync_and_close(self._event_handle))
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise ExceptionGroup("evidence stream sync/close failures", errors)

    def _durably_quarantine(self, primary: BaseException) -> None:
        """Best-effort persistence without replacing the sealing failure."""

        secondary_diagnostics = _BoundedDiagnostics()

        def record_secondary(error: Exception) -> None:
            secondary_diagnostics.append(
                "secondary durability failure while quarantining evidence: "
                f"{type(error).__name__}: {error}"
            )

        try:
            for scanned_entries, artifact in enumerate(self.staging_path.iterdir()):
                if scanned_entries >= MAX_BUNDLE_ENTRIES:
                    secondary_diagnostics.append(
                        "quarantine inventory limit reached; additional entries omitted"
                    )
                    break
                try:
                    if artifact.is_file() and not artifact.is_symlink():
                        _fsync_file(artifact)
                except Exception as error:  # noqa: BLE001 - preserve primary failure
                    record_secondary(error)
        except Exception as error:  # noqa: BLE001 - preserve the primary failure
            record_secondary(error)

        directories = (
            self.staging_path,
            self.staging_path.parent,
            self.base_dir,
            self.final_path.parent,
        )
        seen: set[Path] = set()
        for directory in directories:
            if directory in seen:
                continue
            seen.add(directory)
            try:
                if directory.is_dir() and not directory.is_symlink():
                    _fsync_directory(directory)
            except Exception as error:  # noqa: BLE001 - preserve the primary failure
                record_secondary(error)

        self._state = "quarantined"
        for diagnostic in secondary_diagnostics:
            primary.add_note(diagnostic)

    def finalise(self, *, status: str, failure_reason: str | None = None) -> Path:
        self._require_open()
        if not isinstance(status, str) or status not in {"complete", "incomplete"}:
            raise ValueError("status must be complete or incomplete")
        if status == "complete" and failure_reason is not None:
            raise ValueError("a complete run cannot have a failure reason")
        if status == "incomplete" and (
            not isinstance(failure_reason, str) or not failure_reason.strip()
        ):
            raise ValueError("an incomplete run requires a failure reason")
        if status == "complete" and self._packet_count == 0:
            raise ValueError("a complete run requires packet evidence")
        if status == "complete" and self._event_count == 0:
            raise ValueError("a complete run requires event evidence")

        self._state = "sealing"
        try:
            self._seal_streams()

            for artifact in _bounded_sorted_directory_entries(self.staging_path):
                if artifact.is_file() and not artifact.is_symlink():
                    _fsync_file(artifact)

            evidence_hashes = {
                path.name: sha256_file(path)
                for path in _bounded_sorted_directory_entries(self.staging_path)
                if path.is_file()
            }
            final_manifest = {
                **self.manifest,
                "status": status,
                "failure_reason": failure_reason,
                "finalised_at_utc": _utc_now(),
                "evidence_sha256": evidence_hashes,
            }
            ensure_no_secrets(final_manifest)
            manifest_path = self.staging_path / "manifest.json"
            _write_text_synced(
                manifest_path,
                json.dumps(final_manifest, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )

            all_hashes = {
                path.name: sha256_file(path)
                for path in _bounded_sorted_directory_entries(self.staging_path)
                if path.is_file() and path.name != "SHA256SUMS"
            }
            sums_path = self.staging_path / "SHA256SUMS"
            _write_text_synced(
                sums_path,
                "".join(
                    f"{digest}  {name}\n" for name, digest in sorted(all_hashes.items())
                ),
                encoding="ascii",
            )
            validation = validate_evidence_bundle(self.staging_path)
            if not validation.valid:
                raise ValueError(
                    format_validation_diagnostics(
                        validation.errors,
                        prefix="refusing to publish invalid evidence bundle: ",
                    )
                )
            _fsync_directory(self.staging_path)
            self.final_path.parent.mkdir(parents=True, exist_ok=True)
            _fsync_directory(self.base_dir)
            _publish_directory_no_replace(self.staging_path, self.final_path)
            self._state = "published"
            return self.final_path
        except BaseException as error:
            self._durably_quarantine(error)
            raise
        finally:
            if self._state == "sealing":
                self._state = "quarantined"


class AttemptEvidenceBundle(EvidenceBundle):
    """Write immutable manifest-v1.2 attempt evidence keyed by attempt UUID."""

    writer_schema_version = CURRENT_MANIFEST_SCHEMA_VERSION
    identity_field = "attempt_id"


def _packet_from_csv(row: dict[str | None, str | list[str] | None]) -> dict[str, Any]:
    if None in row:
        raise ValueError("row contains fields beyond the declared header")

    def integer(field: str, *, nullable: bool = False) -> int | None:
        value = row[field]
        if not isinstance(value, str):
            raise TypeError(f"{field} is missing")
        if nullable and value == "":
            return None
        if not re.fullmatch(r"0|[1-9]\d*", value):
            raise ValueError(f"{field} must be an unsigned decimal integer")
        return int(value)

    def number(field: str, *, nullable: bool = False) -> float | None:
        value = row[field]
        if not isinstance(value, str):
            raise TypeError(f"{field} is missing")
        if nullable and value == "":
            return None
        if not value or value.strip() != value:
            raise ValueError(f"{field} must be a number")
        try:
            parsed = float(value)
        except ValueError as error:
            raise ValueError(f"{field} must be a number") from error
        if not math.isfinite(parsed):
            raise ValueError(f"{field} must be finite")
        return parsed

    path_id = row["path_id"]
    status = row["status"]
    if not isinstance(path_id, str) or not isinstance(status, str):
        raise TypeError("path_id and status must be text")
    return {
        "sequence": integer("sequence"),
        "path_id": path_id,
        "sent_ns": integer("sent_ns"),
        "received_ns": integer("received_ns", nullable=True),
        "status": status,
        "rtt_ms": number("rtt_ms", nullable=True),
        "datagram_bytes": integer("datagram_bytes"),
    }


def _validate_packets_bytes(
    content: bytes, *, complete: bool, strict: bool
) -> list[str]:
    errors = _BoundedDiagnostics()
    sequences: set[int] = set()
    packet_count = 0
    try:
        handle = io.StringIO(content.decode("utf-8"), newline="")
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(PACKET_FIELDS):
            return [
                (
                    "packets.csv header mismatch; "
                    f"expected={list(PACKET_FIELDS)}, actual={reader.fieldnames}"
                )
            ]
        for row in reader:
            packet_count += 1
            try:
                parsed = _packet_from_csv(row)
                _validate_packet_row(parsed, strict=strict)
                sequence = parsed["sequence"]
                if strict and sequence in sequences:
                    raise ValueError(f"duplicate sequence: {sequence}")
                sequences.add(sequence)
            except (OverflowError, RecursionError, TypeError, ValueError) as error:
                errors.append(f"packets.csv line {reader.line_num}: {error}")
                if errors.truncated:
                    break
    except (UnicodeError, csv.Error) as error:
        errors.append(f"packets.csv invalid: {error}")
    if complete and packet_count == 0:
        errors.append("packets.csv has no packet evidence for a complete run")
    return errors


def _validate_events_bytes(
    content: bytes, *, complete: bool, strict: bool
) -> list[str]:
    errors = _BoundedDiagnostics()
    event_count = 0
    try:
        handle = io.BytesIO(content)
        line_number = 0
        while True:
            raw_line = handle.readline(_MAX_JSON_BYTES + 1)
            if not raw_line:
                break
            line_number += 1
            if len(raw_line) > _MAX_JSON_BYTES:
                errors.append(
                    f"events.jsonl line {line_number}: "
                    f"JSON document exceeds {_MAX_JSON_BYTES} bytes"
                )
                while raw_line and not raw_line.endswith(b"\n"):
                    raw_line = handle.readline(_MAX_JSON_BYTES + 1)
                if errors.truncated:
                    break
                continue
            if not raw_line.strip():
                errors.append(f"events.jsonl line {line_number}: blank line")
                if errors.truncated:
                    break
                continue
            try:
                line = raw_line.decode("utf-8")
                event = _load_json_object(line)
                _validate_event(event, strict=strict)
                event_count += 1
            except (
                json.JSONDecodeError,
                RecursionError,
                TypeError,
                ValueError,
            ) as error:
                errors.append(f"events.jsonl line {line_number}: {error}")
                if errors.truncated:
                    break
    except (UnicodeError, ValueError) as error:
        errors.append(f"events.jsonl invalid: {error}")
    if complete and event_count == 0:
        errors.append("events.jsonl has no event evidence for a complete run")
    return errors


def _validate_auxiliary_structured_bytes(name: str, content: bytes) -> list[str]:
    errors = _BoundedDiagnostics()
    suffix = Path(name).suffix.lower()
    try:
        if suffix == ".json":
            value = _load_json_value(content.decode("utf-8"))
            ensure_no_secrets(value, location=name)
        elif suffix == ".jsonl":
            handle = io.BytesIO(content)
            line_number = 0
            while True:
                raw_line = handle.readline(_MAX_JSON_BYTES + 1)
                if not raw_line:
                    break
                line_number += 1
                try:
                    value = _load_json_line(
                        raw_line, label=f"{name} line {line_number}"
                    )
                    ensure_no_secrets(value, location=f"{name}[{line_number}]")
                except (RecursionError, TypeError, UnicodeError, ValueError) as error:
                    errors.append(f"{name} line {line_number}: {error}")
                    if errors.truncated:
                        break
                if len(raw_line) > _MAX_JSON_BYTES:
                    while raw_line and not raw_line.endswith(b"\n"):
                        raw_line = handle.readline(_MAX_JSON_BYTES + 1)
    except (
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        errors.append(f"{name} invalid structured evidence: {error}")
    return errors


def _read_manifest(
    raw_bytes: bytes,
    errors: list[str],
) -> dict[str, Any] | None:
    try:
        manifest = _load_json_object(raw_bytes.decode("utf-8"))
        ensure_no_secrets(manifest)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        errors.append(f"manifest.json invalid: {error}")
        return None
    try:
        errors.extend(_manifest_errors(manifest, require_final=True))
    except (OverflowError, RecursionError, TypeError, ValueError) as error:
        errors.append(f"manifest.json semantic validation failed: {error}")
    return manifest


def _validate_canonical_lf_bytes(
    content: bytes, label: str, errors: list[str]
) -> None:
    forbidden_separators = (
        b"\x0b",
        b"\x0c",
        b"\x1c",
        b"\x1d",
        b"\x1e",
        b"\xc2\x85",
        b"\xe2\x80\xa8",
        b"\xe2\x80\xa9",
    )
    if b"\r" in content or any(
        separator in content for separator in forbidden_separators
    ):
        errors.append(f"{label} must use canonical LF line endings")
        return
    if content and not content.endswith(b"\n"):
        errors.append(f"{label} must end with a terminal LF")


def _reconcile_manifest_evidence(
    manifest: dict[str, Any],
    actual_names: set[str],
    errors: list[str],
    verified_hashes: dict[str, str],
) -> None:
    declared = manifest.get("evidence_sha256")
    if not isinstance(declared, dict):
        return
    expected_names = actual_names - {"manifest.json"}
    declared_names = set(declared)
    missing = expected_names - declared_names
    extra = declared_names - expected_names
    if missing:
        errors.append(
            "manifest evidence_sha256 missing files: "
            + _format_diagnostic_names(missing)
        )
    if extra:
        errors.append(
            "manifest evidence_sha256 has extra files: "
            + _format_diagnostic_names(extra)
        )
    for name, expected in declared.items():
        if not _is_safe_basename(name):
            errors.append(f"manifest evidence_sha256 has unsafe name: {name!r}")
            continue
        if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
            errors.append(f"manifest evidence_sha256 has invalid digest for {name}")
            continue
        if name in expected_names:
            actual = verified_hashes.get(name)
            if actual is None:
                errors.append(f"manifest evidence file {name} was not captured")
                continue
            if actual is not None and actual != expected:
                errors.append(f"manifest evidence_sha256 mismatch for {name}")


def _validate_evidence_bundle(path: Path) -> BundleValidation:
    """Fail closed unless inventory, hashes, and evidence semantics all agree."""
    path = Path(path)
    errors = _BoundedDiagnostics()
    checked: set[str] = set()
    try:
        root_before = os.lstat(path)
    except OSError:
        return BundleValidation(False, ("evidence bundle is not a regular directory",), ())
    if not _is_real_directory_stat(root_before):
        return BundleValidation(False, ("evidence bundle is not a regular directory",), ())

    try:
        inventory = _bounded_sorted_directory_entries(path)
    except (OSError, ValueError) as error:
        return BundleValidation(
            False,
            (f"cannot inventory evidence bundle: {error}",),
            (),
        )

    actual_names: set[str] = set()
    regular_paths: dict[str, Path] = {}
    snapshots: dict[str, FileSnapshot] = {}
    total_bytes = 0
    try:
        for candidate in inventory:
            candidate_stat = os.lstat(candidate)
            if not _is_regular_file_stat(candidate_stat):
                errors.append(f"{candidate.name} is not a regular file")
                continue
            regular_paths[candidate.name] = candidate
            if candidate.name != "SHA256SUMS":
                actual_names.add(candidate.name)
            snapshots[candidate.name] = _file_snapshot(candidate_stat)
            total_bytes += candidate_stat.st_size
    except OSError as error:
        return BundleValidation(False, (f"cannot inventory evidence bundle: {error}",), ())
    if "SHA256SUMS" not in regular_paths:
        return BundleValidation(
            False,
            ("SHA256SUMS is missing or not a regular file",),
            (),
        )
    if total_bytes > MAX_EVIDENCE_BUNDLE_BYTES:
        return BundleValidation(
            False,
            (
                f"evidence bundle exceeds {MAX_EVIDENCE_BUNDLE_BYTES} total bytes",
            ),
            (),
        )

    captured_bytes: dict[str, bytes] = {}
    captured_total_bytes = 0
    for name, candidate in regular_paths.items():
        if name == "SHA256SUMS":
            maximum_bytes = _MAX_INVENTORY_BYTES
        elif name == "manifest.json" or candidate.suffix.lower() == ".json":
            maximum_bytes = _MAX_JSON_BYTES
        else:
            maximum_bytes = MAX_EVIDENCE_ARTIFACT_BYTES
        remaining_bundle_bytes = MAX_EVIDENCE_BUNDLE_BYTES - captured_total_bytes
        if remaining_bundle_bytes < 0:
            errors.append(
                f"evidence bundle exceeds {MAX_EVIDENCE_BUNDLE_BYTES} total bytes"
            )
            break
        capture_limit = min(maximum_bytes, remaining_bundle_bytes)
        try:
            content, snapshot = _read_bounded_regular_bytes(
                candidate,
                maximum_bytes=capture_limit,
                label=name,
            )
            captured_bytes[name] = content
            snapshots[name] = snapshot
            captured_total_bytes += len(content)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"{name} cannot be captured: {error}")

    sums_bytes = captured_bytes.get("SHA256SUMS")
    if sums_bytes is None:
        return BundleValidation(False, tuple(errors), ())
    sums_digest = hashlib.sha256(sums_bytes).hexdigest()
    listed_names: set[str] = set()
    verified_hashes = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in captured_bytes.items()
        if name != "SHA256SUMS"
    }
    try:
        sum_lines = sums_bytes.decode("ascii").splitlines()
    except UnicodeError as error:
        return BundleValidation(False, (f"SHA256SUMS is invalid: {error}",), ())
    if not sum_lines:
        errors.append("SHA256SUMS is empty")
    for line_number, line in enumerate(sum_lines, 1):
        expected, separator, name = line.partition("  ")
        if not separator or not _SHA256_RE.fullmatch(expected) or not _is_safe_basename(name):
            errors.append(f"invalid SHA256SUMS line {line_number}")
            continue
        if name == "SHA256SUMS":
            errors.append(f"SHA256SUMS line {line_number} lists itself")
            continue
        if name in listed_names:
            errors.append(f"duplicate SHA256SUMS entry for {name}")
            continue
        if len(listed_names) >= MAX_BUNDLE_ENTRIES:
            errors.append(
                f"SHA256SUMS has more than {MAX_BUNDLE_ENTRIES} entries"
            )
            break
        listed_names.add(name)
        checked.add(name)
        if name not in actual_names or name not in captured_bytes:
            errors.append(f"{name} is missing or not a regular file")
        else:
            actual = verified_hashes[name]
            if actual != expected:
                errors.append(f"{name} checksum mismatch")

    unlisted = actual_names - listed_names
    absent = listed_names - actual_names
    if unlisted:
        errors.append(
            "files not covered by SHA256SUMS (not listed): "
            + _format_diagnostic_names(unlisted)
        )
    if absent:
        errors.append(
            "SHA256SUMS lists absent files: "
            + _format_diagnostic_names(absent)
        )
    missing_core = sorted(_CORE_ARTIFACTS - actual_names)
    if missing_core:
        errors.append(f"bundle missing core artifacts: {missing_core}")

    for name in sorted(actual_names - _RESERVED_ARTIFACTS):
        if (
            Path(name).suffix.lower() in {".json", ".jsonl"}
            and name in captured_bytes
        ):
            errors.extend(
                _validate_auxiliary_structured_bytes(name, captured_bytes[name])
            )
            if errors.truncated:
                break

    manifest: dict[str, Any] | None = None
    if "manifest.json" in listed_names and "manifest.json" in captured_bytes:
        manifest = _read_manifest(
            captured_bytes["manifest.json"],
            errors,
        )
    if manifest is not None:
        try:
            contract = MANIFEST_CONTRACTS.get(manifest.get("schema_version"))
        except TypeError:
            contract = None
        identity_field = (
            "attempt_id" if contract is not None and contract.attempt_identity else "run_id"
        )
        identity_value = manifest.get(identity_field)
        if isinstance(identity_value, str) and path.name != identity_value:
            errors.append(
                f"bundle directory does not match manifest {identity_field}: "
                f"directory={path.name}, {identity_field}={identity_value}"
            )
        _reconcile_manifest_evidence(manifest, actual_names, errors, verified_hashes)
        strict_contract = contract is not None and contract.strict_packet_event
        complete = strict_contract and manifest.get("status") == "complete"
        if strict_contract:
            for name in sorted(_CORE_ARTIFACTS | {"SHA256SUMS"}):
                if name in captured_bytes:
                    _validate_canonical_lf_bytes(captured_bytes[name], name, errors)
        if "packets.csv" in captured_bytes:
            errors.extend(
                _validate_packets_bytes(
                    captured_bytes["packets.csv"],
                    complete=complete,
                    strict=strict_contract,
                )
            )
        if "events.jsonl" in captured_bytes:
            errors.extend(
                _validate_events_bytes(
                    captured_bytes["events.jsonl"],
                    complete=complete,
                    strict=strict_contract,
                )
            )

    try:
        root_after = os.lstat(path)
        if (
            not _is_real_directory_stat(root_after)
            or _file_snapshot(root_before) != _file_snapshot(root_after)
        ):
            errors.append("evidence bundle directory identity or metadata changed")
    except OSError as error:
        errors.append(f"evidence bundle directory changed after validation: {error}")
    _verify_file_snapshots(path, snapshots, errors)
    valid = not errors
    return BundleValidation(
        valid,
        tuple(errors),
        tuple(sorted(checked)),
        manifest if valid else None,
        sums_digest if valid else None,
        captured_bytes if valid else None,
    )


def validate_evidence_bundle(path: Path) -> BundleValidation:
    """Return an invalid result for any ordinary artifact-processing failure."""
    try:
        return _validate_evidence_bundle(path)
    except Exception as error:  # noqa: BLE001 - public untrusted-artifact boundary
        return BundleValidation(
            False,
            (f"bundle validation failed: {type(error).__name__}: {error}",),
            (),
        )
