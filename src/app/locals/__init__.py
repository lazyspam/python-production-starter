"""Message catalog: `msg.auth.invalid_credentials`. Add a language by loading another folder of the same JSON."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

msg: Any = SimpleNamespace(**{p.stem: SimpleNamespace(**json.loads(p.read_text())) for p in Path(__file__).parent.glob("*.json")})
