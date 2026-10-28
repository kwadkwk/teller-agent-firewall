"""MCP-side controls: OAuth 2.1 token checks and tool-description pinning.

Two real MCP risks this addresses:

1. Token passthrough / confused deputy. A tool server must only accept tokens
   minted for *it* (the `aud` claim, RFC 8707 resource indicators). A token the
   agent got for some other API is rejected, even if it is otherwise valid.
2. Tool poisoning / "rug pull". An MCP server can change a tool's description
   after you approved it, slipping new instructions to the model. We pin a
   hash of every approved tool definition and block on any change.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Token:
    """The claims the gateway cares about from a validated OAuth 2.1 access token.

    Signature validation happens upstream (your IdP's JWKS). This class models
    the authorization decision that comes after.
    """

    sub: str                      # the customer the agent acts for
    aud: str                      # the resource this token was minted for
    scopes: frozenset[str]
    issued_at: float = field(default_factory=time.time)

    def has(self, scope: str) -> bool:
        return scope in self.scopes


class TokenError(Exception):
    pass


def check_token(token: Token, *, audience: str, max_age: int, now: float | None = None) -> None:
    now = time.time() if now is None else now
    if token.aud != audience:
        raise TokenError(
            f"Token audience '{token.aud}' is not this tool server ('{audience}'). "
            "Rejected to prevent token passthrough."
        )
    if now - token.issued_at > max_age:
        raise TokenError("Token is older than the allowed lifetime.")


def fingerprint(tool_def: dict) -> str:
    """Stable hash of a tool's name, description and input schema."""
    schema = tool_def.get("inputSchema", tool_def.get("input_schema"))  # MCP or Messages-API spelling
    canon = json.dumps(
        {"name": tool_def.get("name"), "description": tool_def.get("description"), "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canon.encode()).hexdigest()


class ToolRegistry:
    """Approved tools and their pinned fingerprints."""

    def __init__(self) -> None:
        self._pins: dict[str, str] = {}

    def approve(self, tool_def: dict) -> str:
        fp = fingerprint(tool_def)
        self._pins[tool_def["name"]] = fp
        return fp

    def verify(self, tool_def: dict) -> tuple[bool, str]:
        name = tool_def.get("name", "")
        if name not in self._pins:
            return False, f"Tool '{name}' was never approved."
        if fingerprint(tool_def) != self._pins[name]:
            return False, f"Tool '{name}' changed since approval (possible tool poisoning)."
        return True, "Pinned definition matches."
