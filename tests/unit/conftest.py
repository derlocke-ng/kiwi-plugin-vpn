"""Exercise the module exactly as kiwi-fox will: load module/provider.py by file
path, against a sibling kiwi-fox checkout (or KIWI_FOX_SRC). If kiwi-fox is not
present the whole module is skipped, so the tests stay runnable in CI without it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _find_kiwi_fox_src() -> Path | None:
    env = os.environ.get("KIWI_FOX_SRC")
    candidates = [Path(env)] if env else []
    candidates += [REPO.parent / "kiwi-fox" / "src", Path.home() / "kiwi-fox" / "src"]
    for c in candidates:
        if (c / "kiwi_fox" / "core" / "providers" / "base.py").exists():
            return c
    return None


_src = _find_kiwi_fox_src()
if _src and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

pytest.importorskip(
    "kiwi_fox.core.providers.base",
    reason="kiwi-fox not found; clone it beside this repo or set KIWI_FOX_SRC",
)


def _load_module():
    path = REPO / "module" / "provider.py"
    spec = importlib.util.spec_from_file_location("kiwi_plugin_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def module():
    return _load_module()


@pytest.fixture
def provider(module):
    return module.PROVIDER


@pytest.fixture
def manifest(module):
    return module.MANIFEST


@pytest.fixture
def ctx(manifest, tmp_path):
    from kiwi_fox.core.providers.base import ProviderContext

    return ProviderContext(
        name=manifest.name,
        module_dir=REPO / "module",
        state_dir=tmp_path,
        network="kf-providers",
        image=manifest.image or f"kiwi-fox/{manifest.name}:latest",
        socks_port=manifest.socks_port,
    )
