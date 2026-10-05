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


SOURCE_DIR = (
    ROOT
    / "data"
    / "block3"
    / "source"
)

REVIEW_DIR = (
    ROOT
    / "data"
    / "block3"
    / "reviews"
)

REMEDIATED_DIR = (
    ROOT
    / "data"
    / "block3"
    / "remediated"
)

METADATA_DIR = (
    ROOT
    / "data"
    / "block3"
    / "metadata"
)

RESULTS_DIR = (
    ROOT
    / "results"
    / "block3"
)

PROMPTS_FILE = (
    ROOT
    / "frozen_config"
    / "block3_prompts.json"
)


for directory in [
    REVIEW_DIR,
    REMEDIATED_DIR,
    METADATA_DIR,
    RESULTS_DIR,
]:
    directory.mkdir(
        parents=True,
        exist_ok=True
    )


prompts = json.loads(
    PROMPTS_FILE.read_text(
        encoding="utf-8"
    )
)


def sha256_text(text):

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def extract_json(text):

    text = text.strip()

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

        start = text.find("{")
        end = text.rfind("}")

        if (
            start >= 0
            and end > start
        ):
            return json.loads(
                text[start:end + 1]
            )

        raise


def extract_code(text):

    text = text.strip()

    match = re.fullmatch(
        r"```(?:python)?\s*(.*?)\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    if match:
        text = match.group(1).strip()

    return text


source_files = sorted(
    SOURCE_DIR.glob("*.py")
)

total = len(source_files)

completed = 0
skipped = 0
errors = 0

error_log = (
    RESULTS_DIR
    / "block3_llm_errors.log"
)


print("=" * 60)
print("EXPERIMENTO DEFINITIVO - BLOQUE III")
print("=" * 60)
print("Modelo           :", MODEL)
print("Reasoning effort :", REASONING)
print("Muestras         :", total)
print("=" * 60)


for position, source_file in enumerate(
    source_files,
    start=1
):

    sample_id = source_file.stem

    review_file = (
        REVIEW_DIR
        / f"{sample_id}.json"
    )

    remediated_file = (
        REMEDIATED_DIR
        / f"{sample_id}.py"
    )

    metadata_file = (
        METADATA_DIR
        / f"{sample_id}.json"
    )


    # ------------------------------------------
    # Reanudación segura
    # ------------------------------------------

    if (
        review_file.exists()
        and remediated_file.exists()
        and metadata_file.exists()
    ):

        skipped += 1

        print(
            f"[{position:02d}/{total}] "
            f"SKIP {sample_id}"
        )

        continue


    code = source_file.read_text(
        encoding="utf-8"
    )

    print(
        f"[{position:02d}/{total}] "
        f"{sample_id}"
    )


    try:

        # ======================================
        # ETAPA 1 - REVIEW
        # ======================================

        review_prompt = prompts[
            "user_review"
        ].replace(
            "{code}",
            code
        )

        review_response = (
            client.responses.create(
                model=MODEL,
                reasoning={
                    "effort":
                        REASONING
                },
                max_output_tokens=4000,
                input=[
                    {
                        "role":
                            "system",
                        "content":
                            prompts[
                                "system_review"
                            ],
                    },
                    {
                        "role":
                            "user",
                        "content":
                            review_prompt,
                    },
                ],
            )
        )

        review_raw = (
            review_response
            .output_text
            .strip()
        )

        review = extract_json(
            review_raw
        )

        vulnerabilities = review.get(
            "vulnerabilities",
            []
        )

        if not isinstance(
            vulnerabilities,
            list
        ):
            raise ValueError(
                "vulnerabilities "
                "no es una lista"
            )


        review_file.write_text(
            json.dumps(
                {
                    "sample_id":
                        sample_id,

                    "model":
                        review_response.model,

                    "response_id":
                        review_response.id,

                    "review":
                        review,

                    "raw_response":
                        review_raw,
                },
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )


        print(
            "     REVIEW"
            f" | hallazgos="
            f"{len(vulnerabilities)}"
        )


        # ======================================
        # ETAPA 2 - REMEDIATION
        # ======================================

        review_for_prompt = json.dumps(
            review,
            ensure_ascii=False,
            indent=2
        )

        remediation_prompt = prompts[
            "user_remediation"
        ]

        remediation_prompt = (
            remediation_prompt
            .replace(
                "{code}",
                code
            )
            .replace(
                "{review}",
                review_for_prompt
            )
        )


        remediation_response = (
            client.responses.create(
                model=MODEL,
                reasoning={
                    "effort":
                        REASONING
                },
                max_output_tokens=6000,
                input=[
                    {
                        "role":
                            "system",
                        "content":
                            prompts[
                                "system_remediation"
                            ],
                    },
                    {
                        "role":
                            "user",
                        "content":
                            remediation_prompt,
                    },
                ],
            )
        )


        remediated_code = (
            extract_code(
                remediation_response
                .output_text
            )
        )


        if not remediated_code.strip():
            raise ValueError(
                "Código remediado vacío"
            )


        remediated_file.write_text(
            remediated_code,
            encoding="utf-8"
        )


        # ======================================
        # METADATOS
        # ======================================

        metadata = {

            "sample_id":
                sample_id,

            "experiment":
                "TFM_Block3_Final",

            "model_requested":
                MODEL,

            "model_review":
                review_response.model,

            "model_remediation":
                remediation_response.model,

            "reasoning_effort":
                REASONING,

            "review_response_id":
                review_response.id,

            "remediation_response_id":
                remediation_response.id,

            "executed_at_utc":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "review_findings":
                len(vulnerabilities),

            "source_sha256":
                sha256_text(
                    code
                ),

            "review_sha256":
                sha256_text(
                    review_raw
                ),

            "remediated_sha256":
                sha256_text(
                    remediated_code
                ),

            "review_system_prompt_sha256":
                sha256_text(
                    prompts[
                        "system_review"
                    ]
                ),

            "remediation_system_prompt_sha256":
                sha256_text(
                    prompts[
                        "system_remediation"
                    ]
                ),

            "review_user_prompt_sha256":
                sha256_text(
                    review_prompt
                ),

            "remediation_user_prompt_sha256":
                sha256_text(
                    remediation_prompt
                ),
        }


        metadata_file.write_text(
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )


        completed += 1

        print(
            "     REMEDIATION OK"
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
        ) as f:

            f.write(message)


        print(
            f"     ERROR: {error}"
        )


    time.sleep(0.2)


print()
print("=" * 60)
print("BLOQUE III - ETAPA LLM FINALIZADA")
print("=" * 60)
print("Completadas :", completed)
print("Omitidas    :", skipped)
print("Errores     :", errors)

print(
    "Reviews     :",
    len(
        list(
            REVIEW_DIR.glob(
                "*.json"
            )
        )
    )
)

print(
    "Remediadas  :",
    len(
        list(
            REMEDIATED_DIR.glob(
                "*.py"
            )
        )
    )
)

print(
    "Metadatos   :",
    len(
        list(
            METADATA_DIR.glob(
                "*.json"
            )
        )
    )
)

print("=" * 60)