from pathlib import Path
import json
import os
import re
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]

load_dotenv(ROOT / ".env")

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
REPETITIONS = 2
REASONING = os.getenv("REASONING_EFFORT", "medium")

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

scenarios = json.loads(
    (ROOT / "config" / "scenarios_block1.json")
    .read_text(encoding="utf-8")
)

prompts = json.loads(
    (ROOT / "config" / "prompts.json")
    .read_text(encoding="utf-8")
)

# Solo repetir los escenarios modificados
scenarios = [
    s for s in scenarios
    if s["id"] in ("AUTH", "TOKEN")
]

OUTPUT_DIR = (
    ROOT
    / "data"
    / "pilot_adjusted"
    / "block1"
    / "generated"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def build_prompt(scenario, condition):

    parts = [
        scenario["functional_requirement"]
    ]

    if condition in (
        "NEUTRAL",
        "SECURE"
    ):
        parts.append(
            scenario["technical_context"]
        )

    if condition == "SECURE":
        parts.append(
            scenario["security_requirement"]
        )

    return "\n\n".join(parts)


def clean_code(text):

    text = text.strip()

    match = re.fullmatch(
        r"```(?:python)?\s*(.*?)\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    if match:
        return match.group(1).strip()

    return text


total = (
    len(scenarios)
    * 3
    * REPETITIONS
)

counter = 0

print("-----------------------------------")
print("PILOTO AJUSTADO")
print("-----------------------------------")
print("Escenarios:", len(scenarios))
print("Condiciones: 3")
print("Repeticiones:", REPETITIONS)
print("Total:", total)
print("-----------------------------------")


for scenario in scenarios:

    for condition in (
        "UNDERSPEC",
        "NEUTRAL",
        "SECURE"
    ):

        for repetition in range(
            1,
            REPETITIONS + 1
        ):

            counter += 1

            sample_id = (
                f"PILOT2_B1_"
                f"{scenario['id']}_"
                f"{condition}_"
                f"{repetition:02d}"
            )

            code_file = (
                OUTPUT_DIR
                / f"{sample_id}.py"
            )

            metadata_file = (
                OUTPUT_DIR
                / f"{sample_id}.json"
            )

            prompt = build_prompt(
                scenario,
                condition
            )

            print(
                f"[{counter}/{total}] "
                f"{sample_id}"
            )

            response = (
                client.responses.create(
                    model=MODEL,
                    reasoning={
                        "effort": REASONING
                    },
                    max_output_tokens=4000,
                    input=[
                        {
                            "role": "system",
                            "content":
                                prompts[
                                    "system_generation"
                                ]
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
            )

            code = clean_code(
                response.output_text
            )

            code_file.write_text(
                code + "\n",
                encoding="utf-8"
            )

            metadata = {
                "sample_id": sample_id,
                "pilot": True,
                "pilot_version": 2,
                "scenario_id":
                    scenario["id"],
                "scenario_name":
                    scenario["name"],
                "condition":
                    condition,
                "repetition":
                    repetition,
                "model_requested":
                    MODEL,
                "model_returned":
                    response.model,
                "reasoning_effort":
                    REASONING,
                "response_id":
                    response.id,
                "executed_at_utc":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),
                "prompt":
                    prompt
            }

            metadata_file.write_text(
                json.dumps(
                    metadata,
                    ensure_ascii=False,
                    indent=2
                ),
                encoding="utf-8"
            )

            print("     OK")

            time.sleep(0.2)


print("-----------------------------------")
print("PILOTO AJUSTADO FINALIZADO")
print("-----------------------------------")