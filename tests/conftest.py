from pathlib import Path

import pytest

from firewall import Gateway, Policy, Session, Token, ToolRegistry

ROOT = Path(__file__).resolve().parents[1]
AUD = "https://tools.tellerbank.example"


@pytest.fixture
def policy():
    return Policy.load(ROOT / "policy.yaml")


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def gw(policy, registry):
    return Gateway(policy, registry=registry)


@pytest.fixture
def session():
    return Session(
        customer_id="C-1042",
        token=Token(sub="C-1042", aud=AUD, scopes=frozenset({"accounts:read", "transfers:self", "docs:read"})),
        owned_accounts={"CHK-4417", "SAV-8802"},
        known_payees={"Comcast", "Eversource", "Oak Street Apts"},
    )
