# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# https://vaultra.io
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
conftest.py — shared, whole-suite test fixtures.

Fix-round follow-up to Task 1.7 (F21 1/4): ``AgentIdentity.__init__`` gained a
real filesystem default (``key_path`` = ``~/.vaultra/keys/<agent_id>.pem``)
where none existed before. Any test that builds an ``AgentIdentity`` — or a
``VaultraPipeline``, which builds one internally — without passing an explicit
``key_path`` was silently reading/writing real private-key PEM files into the
actual developer's (or CI runner's) real home directory on every ``pytest``
run, accumulating indefinitely.

The autouse fixture below redirects ``Path.home()`` to a per-test ``tmp_path``
for the whole suite, so that default resolves inside pytest's own managed
temp-file area (cleaned up automatically) instead of the real home directory.
This requires no changes to the call sites themselves.
"""

import pathlib

import pytest


@pytest.fixture(autouse=True)
def isolate_vaultra_key_home(tmp_path, monkeypatch):
    """Redirect ``Path.home()`` to ``tmp_path`` for every test in the suite.

    ``AgentIdentity._load_or_generate_key`` (vaultra/identity.py) resolves its
    default ``key_path`` via ``Path.home() / ".vaultra" / "keys" / ...`` when
    no explicit ``key_path`` is given. Patching ``Path.home`` here — rather
    than in each test — isolates that I/O for every existing and future call
    site (direct ``AgentIdentity(...)`` construction, or indirectly via
    ``VaultraPipeline(...)``) without requiring each one to opt in.
    """
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
