"""Expose only the future Web3 pack source to its focused tests."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACK_SOURCE = ROOT / "packs" / "web3" / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PACK_SOURCE))
