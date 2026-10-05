from pathlib import Path
import json
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

SOURCE_DIR = (
    ROOT
    / "data"
    / "block3"
    / "remediated"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "block3"
    / "semgrep_post"
)

RESULTS_DIR = (
    ROOT
    / "results"
    / "block3"
)

RULES_DIR = (
    ROOT
    / "tools"
    / "semgrep-rules"
    / "python"
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# --------------------------------------------------
# Verificaciones
# --------------------------------------------------

semgrep_exe = shutil.which(
    "semgrep"
)

if semgrep_exe is None:
    raise RuntimeError(
        "No se encontró Semgrep "
        "en el entorno activo."
    )

if not RULES_DIR.exists():
    raise RuntimeError(
        f"No existe el conjunto "
        f"de reglas congeladas: "
        f"{RULES_DIR}"
    )

source_files = sorted(
    SOURCE_DIR.glob("*.py")
)

if not source_files:
    raise RuntimeError(
        "No se encontraron "
        "archivos remediados."
    )


total = len(source_files)

completed = 0
skipped = 0
errors = 0
total_raw_findings = 0


error_log = (
    RESULTS_DIR
    / "block3_semgrep_errors.log"
)


print("=" * 60)
print("SAST POST - BLOQUE III")
print("=" * 60)

print(
    "Semgrep:",
    semgrep_exe
)

print(
    "Reglas:",
    RULES_DIR
)

print(
    "Archivos:",
    total
)

print("=" * 60)


for position, source_file in enumerate(
    source_files,
    start=1
):

    sample_id = source_file.stem

    output_file = (
        OUTPUT_DIR
        / f"{sample_id}.json"
    )


    # ------------------------------------------
    # Reanudación segura
    # ------------------------------------------

    if output_file.exists():

        try:

            existing = json.loads(
                output_file.read_text(
                    encoding="utf-8"
                )
            )

            if (
                isinstance(existing, dict)
                and "results" in existing
            ):

                skipped += 1

                findings = len(
                    existing.get(
                        "results",
                        []
                    )
                )

                total_raw_findings += (
                    findings
                )

                print(
                    f"[{position:02d}/{total}] "
                    f"SKIP {sample_id}"
                    f" | findings={findings}"
                )

                continue

        except Exception:
            pass


    print(
        f"[{position:02d}/{total}] "
        f"Analizando {sample_id}"
    )


    command = [
        semgrep_exe,
        "scan",
        "--config",
        str(RULES_DIR),
        "--json",
        "--metrics=off",
        "--quiet",
        str(source_file),
    ]


    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )


        stdout = (
            result.stdout.strip()
        )


        if not stdout:

            raise RuntimeError(
                "Semgrep no devolvió JSON. "
                f"stderr={result.stderr}"
            )


        data = json.loads(
            stdout
        )


        if "results" not in data:

            raise RuntimeError(
                "La salida de Semgrep "
                "no contiene 'results'."
            )


        output_file.write_text(
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )


        findings = len(
            data.get(
                "results",
                []
            )
        )


        total_raw_findings += (
            findings
        )

        completed += 1


        print(
            f"     OK"
            f" | raw_findings="
            f"{findings}"
        )


    except Exception as error:

        errors += 1

        message = (
            f"{sample_id}: "
            f"{type(error).__name__}: "
            f"{error}\n"
        )

        with error_log.open(
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                message
            )


        print(
            f"     ERROR: {error}"
        )


print()
print("=" * 60)
print("SAST POST BLOQUE III FINALIZADO")
print("=" * 60)

print(
    "Analizadas :",
    completed
)

print(
    "Omitidas   :",
    skipped
)

print(
    "Errores    :",
    errors
)

print(
    "JSON totales:",
    len(
        list(
            OUTPUT_DIR.glob(
                "*.json"
            )
        )
    )
)

print(
    "Raw findings totales:",
    total_raw_findings
)

print("=" * 60)