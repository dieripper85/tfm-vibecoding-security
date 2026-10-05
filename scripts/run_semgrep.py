from pathlib import Path
import subprocess, os
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
CONFIG = os.getenv("SEMGREP_CONFIG", "auto")

src = ROOT/"data/block1/generated"
out = ROOT/"data/block1/semgrep"
out.mkdir(parents=True, exist_ok=True)

for code in sorted(src.glob("B1_*.py")):
    target = out / f"{code.stem}.json"
    cmd = ["semgrep", "scan", "--config", CONFIG, "--json", str(code)]
    print("SCAN", code.name)
    with target.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
    if proc.returncode not in (0, 1):
        print("ERROR", code.name, proc.stderr)
