from pathlib import Path
import json
import os
import subprocess
from datetime import datetime, timezone

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

CONFIG = ROOT / "tools" / "semgrep-rules" / "python"

SOURCE_DIR = ROOT / "data" / "block1" / "generated"
OUTPUT_DIR = ROOT / "data" / "block1" / "semgrep"
RESULTS_DIR = ROOT / "results"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

files = sorted(SOURCE_DIR.glob("B1_*.py"))

total = len(files)
completed = 0
skipped = 0
errors = 0

error_log = RESULTS_DIR / "block1_semgrep_errors.log"

print("=" * 60)
print("SAST DEFINITIVO - BLOQUE I")
print("=" * 60)
print("Configuracion :", CONFIG)
print("Muestras      :", total)
print("=" * 60)

for index, code_file in enumerate(files, start=1):

    output_file = OUTPUT_DIR / f"{code_file.stem}.json"

    # Si ya existe un JSON válido, no repetir análisis
    if output_file.exists():
        try:
            data = json.loads(
                output_file.read_text(encoding="utf-8")
            )

            if "results" in data:
                skipped += 1
                print(
                    f"[{index:02d}/{total}] "
                    f"SKIP {code_file.name}"
                )
                continue

        except Exception:
            # JSON incompleto/corrupto: se vuelve a generar
            pass

    print(
        f"[{index:02d}/{total}] "
        f"Analizando {code_file.name}"
    )

    command = [
        "semgrep",
        "scan",
        "--config",
        str(CONFIG),
        "--json",
        "--quiet",
        str(code_file)
    ]

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        # Semgrep devuelve el JSON por stdout
        if process.stdout.strip():

            try:
                data = json.loads(process.stdout)

                output_file.write_text(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                        indent=2
                    ),
                    encoding="utf-8"
                )

                findings = len(
                    data.get("results", [])
                )

                completed += 1

                print(
                    f"     OK | hallazgos={findings}"
                )

            except json.JSONDecodeError as error:

                errors += 1

                message = (
                    f"{datetime.now(timezone.utc).isoformat()} "
                    f"{code_file.name}: "
                    f"JSON inválido: {error}\n"
                )

                with error_log.open(
                    "a",
                    encoding="utf-8"
                ) as log:
                    log.write(message)

                print("     ERROR JSON")

        else:

            errors += 1

            message = (
                f"{datetime.now(timezone.utc).isoformat()} "
                f"{code_file.name}: "
                f"Sin salida JSON. "
                f"stderr={process.stderr}\n"
            )

            with error_log.open(
                "a",
                encoding="utf-8"
            ) as log:
                log.write(message)

            print("     ERROR: sin JSON")

    except Exception as error:

        errors += 1

        message = (
            f"{datetime.now(timezone.utc).isoformat()} "
            f"{code_file.name}: "
            f"{type(error).__name__}: {error}\n"
        )

        with error_log.open(
            "a",
            encoding="utf-8"
        ) as log:
            log.write(message)

        print(f"     ERROR → {error}")


print()
print("=" * 60)
print("SAST FINALIZADO")
print("=" * 60)
print("Analizadas :", completed)
print("Omitidas   :", skipped)
print("Errores    :", errors)
print(
    "JSON totales:",
    len(list(OUTPUT_DIR.glob("B1_*.json")))
)
print("=" * 60)