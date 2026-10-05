from pathlib import Path
import json, os, re, time
from datetime import datetime, timezone
from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
REPETITIONS = int(os.getenv("REPETITIONS", "5"))
REASONING = os.getenv("REASONING_EFFORT", "medium")

scenarios = json.loads((ROOT/"frozen_config/scenarios_block1.json").read_text(encoding="utf-8"))
prompts = json.loads((ROOT/"frozen_config/prompts.json").read_text(encoding="utf-8"))
out_dir = ROOT/"data/block1/generated"
out_dir.mkdir(parents=True, exist_ok=True)

client = OpenAI()

def build_prompt(sc, condition):
    parts = [sc["functional_requirement"]]
    if condition in ("NEUTRAL", "SECURE"):
        parts.append(sc["technical_context"])
    if condition == "SECURE":
        parts.append(sc["security_requirement"])
    return "\n\n".join(parts)

def strip_fence(text):
    text = text.strip()
    m = re.fullmatch(r"```(?:python)?\s*(.*?)\s*```", text, flags=re.S|re.I)
    return m.group(1).strip() if m else text

for sc in scenarios:
    for condition in ("UNDERSPEC", "NEUTRAL", "SECURE"):
        for rep in range(1, REPETITIONS + 1):
            sample_id = f"B1_{sc['id']}_{condition}_{rep:02d}"
            py_path = out_dir / f"{sample_id}.py"
            meta_path = out_dir / f"{sample_id}.json"
            if py_path.exists() and meta_path.exists():
                print("SKIP", sample_id)
                continue

            prompt = build_prompt(sc, condition)
            started = datetime.now(timezone.utc).isoformat()
            response = client.responses.create(
                model=MODEL,
                reasoning={"effort": REASONING},
                max_output_tokens=4000,
                input=[
                    {"role": "system", "content": prompts["system_generation"]},
                    {"role": "user", "content": prompt},
                ],
            )
            code = strip_fence(response.output_text)
            py_path.write_text(code + "\n", encoding="utf-8")
            meta = {
                "sample_id": sample_id,
                "block": 1,
                "scenario_id": sc["id"],
                "scenario_name": sc["name"],
                "condition": condition,
                "repetition": rep,
                "requested_model": MODEL,
                "returned_model": getattr(response, "model", None),
                "response_id": getattr(response, "id", None),
                "reasoning_effort": REASONING,
                "executed_at_utc": started,
                "prompt": prompt,
            }
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            print("OK", sample_id)
            time.sleep(0.2)
