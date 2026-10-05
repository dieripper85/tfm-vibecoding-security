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

MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.6-sol"
)

REASONING = os.getenv(
    "REASONING_EFFORT",
    "medium"
)

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


REFERENCE_DIR = (
    ROOT
    / "data"
    / "block2"
    / "reference"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "block2"
    / "reviews"
)

RESULTS_DIR = (
    ROOT
    / "results"
    / "block2"
)

PROMPT_FILE = (
    ROOT
    / "frozen_config"
    / "block2_review_prompt.json"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


prompts = json.loads(
    PROMPT_FILE.read_text(
        encoding="utf-8"
    )
)

SYSTEM_PROMPT = prompts[
    "system_review"
]

USER_TEMPLATE = prompts[
    "user_review"
]


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def extract_json(text):

    text = text.strip()

    # Eliminar bloque Markdown si apareciera
    match = re.fullmatch(
        r"```(?:json)?\s*(.*?)\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    if match:
        text = match.group(1).strip()

    try:
        return json.loads(text)

    except json.JSONDecodeError:

        # Intentar recuperar el primer objeto JSON
        start = text.find("{")
        end = text.rfind("}")

        if (
            start != -1
            and end != -1
            and end > start
        ):
            return json.loads(
                text[start:end + 1]
            )

        raise


code_files = sorted(
    REFERENCE_DIR.glob(
        "B2_*.py"
    )
)

total = len(code_files)

completed = 0
skipped = 0
errors = 0

error_log = (
    RESULTS_DIR
    / "block2_review_errors.log"
)


print("=" * 60)
print("EXPERIMENTO DEFINITIVO - BLOQUE II")
print("=" * 60)
print("Modelo            :", MODEL)
print("Reasoning effort  :", REASONING)
print("Muestras          :", total)
print("=" * 60)


for index, code_file in enumerate(
    code_files,
    start=1
):

    sample_id = code_file.stem

    output_file = (
        OUTPUT_DIR
        / f"{sample_id}.json"
    )

    # Reanudación segura
    if output_file.exists():

        try:
            existing = json.loads(
                output_file.read_text(
                    encoding="utf-8"
                )
            )

            if (
                "review"
                in existing
                and "response_id"
                in existing
            ):
                skipped += 1

                print(
                    f"[{index:02d}/{total}] "
                    f"SKIP {sample_id}"
                )

                continue

        except Exception:
            pass

    code = code_file.read_text(
        encoding="utf-8"
    )

    # IMPORTANTE:
    # Solo código fuente.
    # No se carga el JSON de ground truth.
    user_prompt = USER_TEMPLATE.replace(
        "{code}",
        code
    )

    print(
        f"[{index:02d}/{total}] "
        f"Revisando {sample_id}"
    )

    try:

        response = client.responses.create(
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
                        user_prompt
                }
            ]
        )

        raw_response = (
            response.output_text.strip()
        )

        parse_error = None

        try:
            review = extract_json(
                raw_response
            )

        except Exception as error:

            review = {
                "vulnerabilities": []
            }

            parse_error = (
                f"{type(error).__name__}: "
                f"{error}"
            )

        if not isinstance(
            review.get(
                "vulnerabilities",
                []
            ),
            list
        ):
            raise ValueError(
                "vulnerabilities "
                "no es una lista"
            )

        result = {
            "sample_id":
                sample_id,

            "experiment":
                "TFM_Block2_Final",

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

            "code_sha256":
                sha256_text(code),

            "system_prompt_sha256":
                sha256_text(
                    SYSTEM_PROMPT
                ),

            "user_prompt_sha256":
                sha256_text(
                    user_prompt
                ),

            "review":
                review,

            "raw_response":
                raw_response,

            "parse_error":
                parse_error
        }

        output_file.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        vulnerabilities = review.get(
            "vulnerabilities",
            []
        )

        completed += 1

        print(
            "     OK"
            f" | vulnerabilidades="
            f"{len(vulnerabilities)}"
        )

    except Exception as error:

        errors += 1

        message = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"{sample_id}: "
            f"{type(error).__name__}: "
            f"{error}\n"
        )

        with error_log.open(
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
print("REVISION BLOQUE II FINALIZADA")
print("=" * 60)
print("Revisadas :", completed)
print("Omitidas  :", skipped)
print("Errores   :", errors)
print(
    "JSON totales:",
    len(
        list(
            OUTPUT_DIR.glob(
                "B2_*.json"
            )
        )
    )
)
print("=" * 60)