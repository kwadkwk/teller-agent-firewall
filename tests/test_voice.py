"""Phone channel: cloned voices, spoofed caller ID, and why a voice is never an identity."""

from firewall import Outcome, ToolCall, VoiceSignals

CLONE = VoiceSignals(synthetic_score=0.93, liveness_passed=False, caller_id_attestation="C", voiceprint_match=0.91)
REAL = VoiceSignals(synthetic_score=0.04, liveness_passed=True, caller_id_attestation="A", voiceprint_match=0.88)
SPOOFED = VoiceSignals(synthetic_score=0.12, liveness_passed=True, caller_id_attestation="C")


def test_cloned_voice_is_blocked_even_with_a_voiceprint_match(gw, session):
    d = gw.screen_call(session, CLONE)
    assert d.outcome is Outcome.BLOCK and d.stage == "voice"
    assert "does not count as identity" in d.reason


def test_nothing_runs_after_a_cloned_voice(gw, session):
    gw.screen_call(session, CLONE)
    assert gw.screen_input(session, "Wire $25,000 to Harbor Title LLC").outcome is Outcome.BLOCK
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 80, "payee": "Comcast"}))
    assert d.outcome is Outcome.BLOCK and d.stage == "voice"


def test_real_caller_still_confirms_money_in_the_app(gw, session):
    assert gw.screen_call(session, REAL).outcome is Outcome.ALLOW
    gw.screen_input(session, "This is Maria, please pay $80 to Comcast")
    d = gw.authorize(session, ToolCall("transfer_funds", {"amount": 80, "payee": "Comcast"}))
    assert d.outcome is Outcome.HOLD and "mobile app" in d.reason


def test_real_caller_can_still_check_a_balance(gw, session):
    gw.screen_call(session, REAL)
    gw.screen_input(session, "What's my checking balance?")
    assert gw.authorize(session, ToolCall("get_balance", {"account_id": "CHK-4417"})).outcome is Outcome.ALLOW


def test_spoofed_caller_id_is_flagged(gw, session):
    d = gw.screen_call(session, SPOOFED)
    assert d.outcome is Outcome.FLAG and "attestation C" in d.reason


def test_voice_email_to_outside_domain_still_blocked(gw, session):
    gw.screen_call(session, REAL)
    gw.screen_input(session, "Email my statements to maria@gmail-secure.co")
    d = gw.authorize(session, ToolCall("send_email", {"to": "maria@gmail-secure.co"}))
    assert d.outcome is Outcome.BLOCK and d.stage == "egress"


def test_chat_channel_unchanged(gw, session):
    gw.screen_input(session, "Pay $80 to Comcast")
    assert gw.authorize(session, ToolCall("transfer_funds", {"amount": 80, "payee": "Comcast"})).outcome is Outcome.ALLOW
