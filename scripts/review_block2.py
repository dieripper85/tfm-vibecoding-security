from pathlib import Path
import json, os, re, sys
from datetime import datetime, timezone
from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT/".env")
MODEL = os.getenv("OPENAI_MODEL","gpt-5.6-sol")
REASONING = os.getenv("REASONING_EFFORT","medium")
prompts = json.loads((ROOT/"config/prompts.json").read_text(encoding="utf-8"))
client = OpenAI()

src = ROOT/"data/block2/reference"
out = ROOT/"data/block2/reviews"
out.mkdir(parents=True, exist_ok=True)

schema = """Devuelve JSON válido con esta estructura:
{
  "vulnerabilities": [
    {
      "name": "...",
      "location": "...",
      "description": "...",
      "cwe": "CWE-...",
      "severity": "low|medium|high|critical|unknown",
      "recommendation": "..."
    }
  ]
}
Si no identificas vulnerabilidades, devuelve {"vulnerabilities": []}.
"""

for code_file in sorted(src.glob("*.py")):
    meta_file = code_file.with_suffix(".json")
    if not meta_file.exists():
        print("Falta metadata:", meta_file.name)
        continue
    sample_id = code_file.stem
    output_file = out/f"{sample_id}.json"
    if output_file.exists():
        print("SKIP", sample_id); continue

    code = code_file.read_text(encoding="utf-8")
    user_prompt = schema + "\nCódigo a revisar:\n\n" + code
    response = client.responses.create(
        model=MODEL,
        reasoning={"effort":REASONING},
        max_output_tokens=3000,
        input=[
            {"role":"system","content":prompts["system_review"]},
            {"role":"user","content":user_prompt}
        ],
    )
    raw = response.output_text.strip()
    m = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", raw, flags=re.S|re.I)
    if m: raw = m.group(1).strip()
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {"parse_error":True, "raw_response":response.output_text}

    result = {
        "sample_id":sample_id,
        "executed_at_utc":datetime.now(timezone.utc).isoformat(),
        "requested_model":MODEL,
        "returned_model":getattr(response,"model",None),
        "response_id":getattr(response,"id",None),
        "review":parsed
    }
    output_file.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print("OK", sample_id)
