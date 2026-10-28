"""Load and validate the YAML policy into plain Python objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ToolRule:
    name: str
    scope: str
    owner_arg: str | None = None
    untrusted_output: bool = False
    money_movement: bool = False
    egress: bool = False
    intent_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    injection_patterns: tuple[re.Pattern[str], ...]
    tools: dict[str, ToolRule]
    agent_transfer_max: float
    hold_new_payees: bool
    allowed_email_domains: tuple[str, ...]
    mask_account_numbers: bool
    mask_ssn: bool
    expected_audience: str
    max_token_age_seconds: int
    pin_tool_descriptions: bool
    controls: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        if d.get("version") != 1:
            raise ValueError("Unsupported policy version")
        tools = {}
        for name, t in (d.get("tools") or {}).items():
            if "scope" not in t:
                raise ValueError(f"Tool '{name}' has no scope")
            tools[name] = ToolRule(
                name=name,
                scope=t["scope"],
                owner_arg=t.get("owner_arg"),
                untrusted_output=bool(t.get("untrusted_output", False)),
                money_movement=bool(t.get("money_movement", False)),
                egress=bool(t.get("egress", False)),
                intent_args=tuple(t.get("intent_args", ())),
            )
        lim = d.get("limits", {})
        dlp = d.get("dlp", {})
        mcp = d.get("mcp", {})
        return cls(
            injection_patterns=tuple(
                re.compile(p, re.IGNORECASE)
                for p in d.get("input_screening", {}).get("injection_patterns", [])
            ),
            tools=tools,
            agent_transfer_max=float(lim.get("agent_transfer_max", 0)),
            hold_new_payees=bool(lim.get("hold_new_payees", True)),
            allowed_email_domains=tuple(
                x.lower() for x in d.get("egress", {}).get("allowed_email_domains", [])
            ),
            mask_account_numbers=bool(dlp.get("mask_account_numbers", True)),
            mask_ssn=bool(dlp.get("mask_ssn", True)),
            expected_audience=mcp.get("expected_audience", ""),
            max_token_age_seconds=int(mcp.get("max_token_age_seconds", 900)),
            pin_tool_descriptions=bool(mcp.get("pin_tool_descriptions", True)),
            controls=dict(d.get("controls", {})),
        )
