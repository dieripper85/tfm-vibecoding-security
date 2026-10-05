from pathlib import Path
import subprocess
import os

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

CONFIG = os.getenv("SEMGREP_CONFIG", "auto")

SOURCE_DIR = ROOT / "data" / "pilot" / "block1" / "generated"
OUTPUT_DIR = ROOT / "data" / "pilot" / "block1" / "semgrep"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

files = sorted(SOURCE_DIR.glob("PILOT_B1_*.py"))

print("------------------------------------------")
print("ANALISIS SAST - PILOTO BLOQUE I")
print("------------------------------------------")
print("Configuracion:", CONFIG)
print("Muestras:", len(files))
print("------------------------------------------")

for index, code_file in enumerate(files, start=1):

    output_file = OUTPUT_DIR / f"{code_file.stem}.json"

    if output_file.exists():
        print(f"[{index}/{len(files)}] SKIP {code_file.name}")
        continue

    print(f"[{index}/{len(files)}] Analizando {code_file.name}")

    command = [
        "semgrep",
        "scan",
        "--config",
        CONFIG,
        "--json",
        "--quiet",
        str(code_file)
    ]

    with output_file.open("w", encoding="utf-8") as file:
        process = subprocess.run(
            command,
            stdout=file,
            stderr=subprocess.PIPE,
            text=True
        )

    if process.returncode not in (0, 1):
        print("     ERROR")
        print(process.stderr)
    else:
        print("     OK")

print("------------------------------------------")
print("ANALISIS SAST FINALIZADO")
print("------------------------------------------")