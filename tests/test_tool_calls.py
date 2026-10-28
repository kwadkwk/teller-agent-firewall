from firewall import Outcome, ToolCall


def say(gw, session, text):
    assert gw.screen_input(session, text).allowed


def test_unknown_tool_denied_by_default(gw, session):
    d = gw.authorize(session, ToolCall("delete_account", {}))
    assert d.outcome is Outcome.BLOCK and "allowlist" in d.reason


def test_own_balance_allowed(gw, session):
    say(gw, session, "What's my checking balance?")
    assert gw.authorize(session, ToolCall("get_balance", {"account_id": "CHK-4417"})).outcome is Outcome.ALLOW


def test_other_customer_blocked(gw, session):
    say(gw, session, "What's John Smith's SSN?")
    d = gw.authorize(session, ToolCall("lookup_customer", {"customer_id": "C-2210"}))
    assert d.outcome is Outcome.BLOCK and d.stage == "object_access"


def test_missing_scope_blocked(gw, session):
    from dataclasses import replace
    session.token = replace(session.token, scopes=frozenset({"accounts:read"}))
    say(gw, session, "Pay $80 to Comcast")
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 80, "payee": "Comcast"}))
    assert d.outcome is Outcome.BLOCK and "transfers:self" in d.reason


def test_small_transfer_to_known_payee_allowed(gw, session):
    say(gw, session, "Pay $80 to Comcast")
    assert gw.authorize(session, ToolCall("transfer_funds", {"amount": 80, "payee": "Comcast"})).outcome is Outcome.ALLOW


def test_large_transfer_held(gw, session):
    say(gw, session, "Send $12,000 to Oak Street Apts")
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 12000, "payee": "Oak Street Apts"}))
    assert d.outcome is Outcome.HOLD and d.stage == "transaction"


def test_new_payee_held(gw, session):
    say(gw, session, "Send $50 to Jamie Rivera")
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 50, "payee": "Jamie Rivera"}))
    assert d.outcome is Outcome.HOLD and "new payee" in d.reason


def test_model_invented_amount_held_for_confirmation(gw, session):
    say(gw, session, "Pay my Comcast bill")
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 120, "payee": "Comcast"}))
    assert d.outcome is Outcome.HOLD and d.stage == "provenance"


def test_email_to_outside_domain_blocked(gw, session):
    say(gw, session, "Email my statements to maria@gmail-secure.co")
    d = gw.authorize(session, ToolCall("send_email", {"to": "maria@gmail-secure.co"}))
    assert d.outcome is Outcome.BLOCK and d.stage == "egress"


def test_email_to_bank_inbox_allowed(gw, session):
    say(gw, session, "Send my statements to maria@tellerbank.example")
    assert gw.authorize(session, ToolCall("send_email", {"to": "maria@tellerbank.example"})).outcome is Outcome.ALLOW
