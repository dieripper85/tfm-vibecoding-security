from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import time

from dotenv import load_dotenv
from openai import OpenAI


ROOT = Path(__file__).resolve().parents[1]

load_dotenv(ROOT / ".env")

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
REPETITIONS = int(os.getenv("REPETITIONS", "5"))
REASONING = os.getenv("REASONING_EFFORT", "medium")

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

SCENARIOS_FILE = (
    ROOT
    / "frozen_config"
    / "scenarios_block1.json"
)

PROMPTS_FILE = (
    ROOT
    / "frozen_config"
    / "prompts.json"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "block1"
    / "generated"
)

RESULTS_DIR = ROOT / "results"

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


scenarios = json.loads(
    SCENARIOS_FILE.read_text(
        encoding="utf-8"
    )
)

prompts = json.loads(
    PROMPTS_FILE.read_text(
        encoding="utf-8"
    )
)

SYSTEM_PROMPT = prompts["system_generation"]


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


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


conditions = (
    "UNDERSPEC",
    "NEUTRAL",
    "SECURE"
)

total = (
    len(scenarios)
    * len(conditions)
    * REPETITIONS
)

counter = 0
generated = 0
skipped = 0
errors = 0

error_file = (
    RESULTS_DIR
    / "block1_generation_errors.log"
)

print("=" * 60)
print("EXPERIMENTO DEFINITIVO - BLOQUE I")
print("=" * 60)
print("Modelo solicitado :", MODEL)
print("Reasoning effort   :", REASONING)
print("Escenarios         :", len(scenarios))
print("Condiciones        :", len(conditions))
print("Repeticiones       :", REPETITIONS)
print("Total esperado     :", total)
print("=" * 60)


for scenario in scenarios:

    for condition in conditions:

        prompt = build_prompt(
            scenario,
            condition
        )

        for repetition in range(
            1,
            REPETITIONS + 1
        ):

            counter += 1

            sample_id = (
                f"B1_"
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

            # Si ambos existen, la muestra ya está completa.
            if (
                code_file.exists()
                and metadata_file.exists()
            ):
                skipped += 1

                print(
                    f"[{counter:02d}/{total}] "
                    f"SKIP {sample_id}"
                )

                continue

            # Si solo existe uno, se considera muestra incompleta.
            if code_file.exists():
                code_file.unlink()

            if metadata_file.exists():
                metadata_file.unlink()

            print(
                f"[{counter:02d}/{total}] "
                f"Generando {sample_id}"
            )

            executed_at = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

            try:

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
                                    SYSTEM_PROMPT
                            },
                            {
                                "role": "user",
                                "content":
                                    prompt
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
                    "sample_id":
                        sample_id,

                    "experiment":
                        "TFM_Block1_Final",

                    "block":
                        1,

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
                        executed_at,

                    "system_prompt":
                        SYSTEM_PROMPT,

                    "user_prompt":
                        prompt,

                    "system_prompt_sha256":
                        sha256_text(
                            SYSTEM_PROMPT
                        ),

                    "user_prompt_sha256":
                        sha256_text(
                            prompt
                        ),

                    "code_sha256":
                        sha256_text(
                            code
                        )
                }

                metadata_file.write_text(
                    json.dumps(
                        metadata,
                        ensure_ascii=False,
                        indent=2
                    ),
                    encoding="utf-8"
                )

                generated += 1

                print(
                    "     OK"
                    f" | modelo={response.model}"
                )

            except Exception as error:

                errors += 1

                message = (
                    f"{datetime.now(timezone.utc).isoformat()} "
                    f"{sample_id}: "
                    f"{type(error).__name__}: "
                    f"{error}\n"
                )

                with error_file.open(
                    "a",
                    encoding="utf-8"
                ) as log:
                    log.write(message)

                print(
                    f"     ERROR → {error}"
                )

            time.sleep(0.2)


print()
print("=" * 60)
print("GENERACION FINALIZADA")
print("=" * 60)
print("Generadas :", generated)
print("Omitidas  :", skipped)
print("Errores   :", errors)
print(
    "Total .py:",
    len(
        list(
            OUTPUT_DIR.glob("B1_*.py")
        )
    )
)
print("=" * 60)