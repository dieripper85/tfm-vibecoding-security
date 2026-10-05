from pathlib import Path
import json
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]

load_dotenv(ROOT / ".env")

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
REASONING = os.getenv("REASONING_EFFORT", "medium")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Cargar escenarios
scenarios = json.loads(
    (ROOT / "config" / "scenarios_block1.json").read_text(encoding="utf-8")
)

prompts = json.loads(
    (ROOT / "config" / "prompts.json").read_text(encoding="utf-8")
)

# Seleccionamos únicamente el escenario DB
scenario = next(s for s in scenarios if s["id"] == "DB")

# Condición subespecificada:
# solo requisito funcional, sin contexto técnico ni instrucciones de seguridad
prompt = scenario["functional_requirement"]

sample_id = "PILOT_B1_DB_UNDERSPEC_01"

print("Muestra:", sample_id)
print("Modelo:", MODEL)
print("\nPrompt enviado:")
print("--------------------------------")
print(prompt)
print("--------------------------------")

response = client.responses.create(
    model=MODEL,
    reasoning={"effort": REASONING},
    max_output_tokens=4000,
    input=[
        {
            "role": "system",
            "content": prompts["system_generation"]
        },
        {
            "role": "user",
            "content": prompt
        }
    ]
)

code = response.output_text.strip()

# Eliminar ```python si el modelo lo incluyera
match = re.fullmatch(
    r"```(?:python)?\s*(.*?)\s*```",
    code,
    flags=re.DOTALL | re.IGNORECASE
)

if match:
    code = match.group(1).strip()

output_dir = ROOT / "data" / "block1" / "generated"
output_dir.mkdir(parents=True, exist_ok=True)

code_file = output_dir / f"{sample_id}.py"
metadata_file = output_dir / f"{sample_id}.json"

code_file.write_text(code + "\n", encoding="utf-8")

metadata = {
    "sample_id": sample_id,
    "block": 1,
    "scenario": scenario["name"],
    "scenario_id": scenario["id"],
    "condition": "UNDERSPEC",
    "model_requested": MODEL,
    "model_returned": response.model,
    "reasoning_effort": REASONING,
    "response_id": response.id,
    "executed_at_utc": datetime.now(timezone.utc).isoformat(),
    "prompt": prompt
}

metadata_file.write_text(
    json.dumps(metadata, ensure_ascii=False, indent=2),
    encoding="utf-8"
)

print("\nGeneración completada.")
print("Código:", code_file)
print("Metadata:", metadata_file)