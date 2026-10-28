"""Talk to a real LLM agent behind the firewall.

    pip install -e ".[live]"
    export ANTHROPIC_API_KEY=...      # key for the included client
    export TELLER_MODEL=<model id>
    python -m examples.live_agent
"""

import os
from pathlib import Path

from firewall import Gateway, Policy
from firewall.adapters.llm_agent import run_turn

from . import bank
from .demo import new_session, show

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    import anthropic

    client = anthropic.Anthropic()
    model = os.environ["TELLER_MODEL"]
    gw = Gateway(Policy.load(ROOT / "policy.yaml"))
    session = new_session()
    print("Teller (protected). Try: 'summarize loan_estimate.pdf'. Ctrl+C to quit.\n")
    while True:
        text = input("you> ").strip()
        if not text:
            continue
        r = run_turn(client, gw, session, text, bank.TOOL_DEFS, bank.IMPLS, model=model)
        for d in r.decisions:
            show(d)
        print(f"teller> {r.reply}\n")


if __name__ == "__main__":
    main()
