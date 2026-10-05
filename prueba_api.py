from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

response = client.responses.create(
    model=os.getenv("OPENAI_MODEL", "gpt-5.6-sol"),
    reasoning={"effort": "medium"},
    input="Responde únicamente con: API OK"
)

print(response.output_text)
print("Modelo:", response.model)
print("Response ID:", response.id)