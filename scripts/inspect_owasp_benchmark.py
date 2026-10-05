from pathlib import Path
import csv, sys

if len(sys.argv) != 2:
    print("Uso: python scripts/inspect_owasp_benchmark.py /ruta/BenchmarkPython/expectedresults-0.1.csv")
    raise SystemExit(1)

path = Path(sys.argv[1])
with path.open(newline="", encoding="utf-8-sig") as fh:
    reader = csv.reader(fh)
    for i, row in enumerate(reader):
        print(f"Fila {i}: {row}")
        if i >= 10:
            break
