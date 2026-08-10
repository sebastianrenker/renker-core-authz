from __future__ import annotations

import re

import renker_core_authz

EXPECTED_PUBLIC_API = {
    "__version__",
    "Actor",
    "IdentityError",
    "Capability",
    "CapabilityError",
    "PathScope",
    "CapabilityStore",
    "Decision",
    "PolicyResult",
    "evaluate",
    "AuditLog",
    "AuditEvent",
    "AuditError",
    "GuardedFilesystem",
    "GuardResult",
}


def test_all_declares_expected_surface():
    assert set(renker_core_authz.__all__) == EXPECTED_PUBLIC_API


def test_every_public_name_is_importable():
    for name in renker_core_authz.__all__:
        assert hasattr(renker_core_authz, name), name


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", renker_core_authz.__version__)
