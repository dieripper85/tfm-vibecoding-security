from pathlib import Path
import json, os, re, shutil, sys
from datetime import datetime, timezone
from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT/".env")
MODEL = os.getenv("OPENAI_MODEL","gpt-5.6-sol")
REASONING = os.getenv("REASONING_EFFORT","medium")
prompts = json.loads((ROOT/"config/prompts.json").read_text(encoding="utf-8"))
client = OpenAI()

# Uso:
# python scripts/correct_block3.py B1_DB_NEUTRAL_01
if len(sys.argv) != 2:
    print("Uso: python scripts/correct_block3.py SAMPLE_ID")
    raise SystemExit(1)

sid = sys.argv[1]
src_code = ROOT/"data/block1/generated"/f"{sid}.py"
src_sg = ROOT/"data/block1/semgrep"/f"{sid}.json"
if not src_code.exists() or not src_sg.exists():
    raise SystemExit("La muestra o su resultado Semgrep no existe.")

initial_dir = ROOT/"data/block3/initial"
review_dir = ROOT/"data/block3/review"
corrected_dir = ROOT/"data/block3/corrected"
for d in (initial_dir, review_dir, corrected_dir): d.mkdir(parents=True,exist_ok=True)

shutil.copy2(src_code, initial_dir/f"{sid}.py")
code = src_code.read_text(encoding="utf-8")
sg = json.loads(src_sg.read_text(encoding="utf-8"))
findings = []
for f in sg.get("results",[]):
    extra=f.get("extra",{})
    findings.append({
        "rule_id":f.get("check_id"),
        "line":(f.get("start") or {}).get("line"),
        "message":extra.get("message"),
        "severity":extra.get("severity"),
        "metadata":extra.get("metadata",{})
    })

review_prompt = """Revisa el siguiente código desde el punto de vista de seguridad.
Además de tu propia revisión, considera los hallazgos de análisis estático adjuntos.
Devuelve JSON válido con las claves: vulnerabilities (lista) y correction_instructions (lista).
No ejecutes el código.

CODIGO:
""" + code + "\n\nHALLAZGOS_SAST:\n" + json.dumps(findings,ensure_ascii=False,indent=2)

review_resp = client.responses.create(
    model=MODEL,
    reasoning={"effort":REASONING},
    max_output_tokens=3000,
    input=[
        {"role":"system","content":prompts["system_review"]},
        {"role":"user","content":review_prompt}
    ],
)
review_text=review_resp.output_text.strip()
m=re.fullmatch(r"```(?:json)?\s*(.*?)\s*```",review_text,flags=re.S|re.I)
if m: review_text=m.group(1).strip()
try:
    review_obj=json.loads(review_text)
except Exception:
    review_obj={"raw_response":review_resp.output_text}

(review_dir/f"{sid}.json").write_text(json.dumps(review_obj,ensure_ascii=False,indent=2),encoding="utf-8")

correction_prompt = """Corrige el código siguiente manteniendo su funcionalidad.
Aplica las recomendaciones de seguridad suministradas.
Devuelve exclusivamente el archivo Python corregido.

CODIGO:
""" + code + "\n\nREVISION:\n" + json.dumps(review_obj,ensure_ascii=False,indent=2)

corr_resp=client.responses.create(
    model=MODEL,
    reasoning={"effort":REASONING},
    max_output_tokens=4000,
    input=[
        {"role":"system","content":prompts["system_correction"]},
        {"role":"user","content":correction_prompt}
    ],
)
corrected=corr_resp.output_text.strip()
m=re.fullmatch(r"```(?:python)?\s*(.*?)\s*```",corrected,flags=re.S|re.I)
if m: corrected=m.group(1).strip()
(corrected_dir/f"{sid}.py").write_text(corrected+"\n",encoding="utf-8")
print("Código corregido:", corrected_dir/f"{sid}.py")
print("Ejecuta Semgrep sobre el archivo corregido usando la misma configuración que en Bloque I.")
