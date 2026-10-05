# Laboratorio experimental TFM — SDLC, Vibe Coding y seguridad

Este proyecto implementa los tres bloques experimentales definidos en la metodología.

## 1. Entorno recomendado

- Python 3.14.x
- Semgrep Community Edition
- OpenAI API
- Modelo fijado durante toda la ejecución: `gpt-5.6-sol`

La documentación actual de OpenAI indica que `gpt-5.6-sol` está disponible mediante Responses API. Para reproducibilidad, registra el modelo devuelto por la API en cada ejecución.

## 2. Instalación

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate       # Windows

pip install -r requirements.txt
pip install semgrep
cp .env.example .env
```

Edita `.env` e incorpora `OPENAI_API_KEY`.

## 3. Piloto antes del experimento final

Primero usa:

```env
REPETITIONS=2
```

para validar prompts y cobertura SAST. Cuando el protocolo quede congelado cambia a:

```env
REPETITIONS=5
```

No modifiques escenarios, prompts, modelo ni reglas una vez iniciado el experimento final.

## 4. Bloque I — Generación

Seis escenarios × tres condiciones de prompt × cinco repeticiones = **90 muestras**.

Condiciones:

- `UNDERSPEC`: requisito funcional únicamente.
- `NEUTRAL`: requisito funcional + contexto técnico.
- `SECURE`: requisito funcional + contexto técnico + requisitos de seguridad.

Ejecuta:

```bash
python scripts/generate_block1.py
```

Las muestras y su metadata quedan en:

```text
data/block1/generated/
```

## 5. Análisis Semgrep

Para el piloto puede utilizarse `SEMGREP_CONFIG=auto`.

```bash
python scripts/run_semgrep.py
python scripts/aggregate_block1.py
```

Resultados:

```text
results/block1_findings.csv
results/block1_summary.csv
```

### Importante para el experimento final

`auto` puede cambiar con el tiempo. Antes de producir los datos definitivos debes congelar la versión de Semgrep y el conjunto exacto de reglas utilizado. Registra:

```bash
semgrep --version
python --version
```

y conserva la configuración/reglas usadas junto con el TFM.

## 6. Bloque II — Revisión de vulnerabilidades conocidas

Fuente propuesta: OWASP Benchmark for Python.

Clona el repositorio oficial por separado:

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git
```

El repositorio incluye `testcode/` y `expectedresults-0.1.csv`.

Antes de automatizar la selección, inspecciona el formato real del CSV:

```bash
python scripts/inspect_owasp_benchmark.py /ruta/BenchmarkPython/expectedresults-0.1.csv
```

Para el TFM se propone seleccionar 5 muestras vulnerables para cada una de 6 CWE, es decir **30 muestras vulnerables**. Copia cada fragmento seleccionado a:

```text
data/block2/reference/B2_CWE89_01.py
```

y crea al lado:

```text
data/block2/reference/B2_CWE89_01.json
```

con al menos:

```json
{
  "sample_id": "B2_CWE89_01",
  "source": "OWASP Benchmark Python",
  "original_test_id": "...",
  "expected_cwe": "CWE-89",
  "expected_vulnerability": true
}
```

Luego ejecuta:

```bash
python scripts/review_block2.py
```

El LLM NO recibe la CWE esperada.

## 7. Bloque III — Integración de controles

Selecciona inicialmente 3 escenarios representativos del Bloque I que tengan hallazgos confirmados. Usa una muestra base por escenario o, si el tiempo lo permite, varias repeticiones.

Ejemplo:

```bash
python scripts/correct_block3.py B1_DB_NEUTRAL_01
```

El script:

1. conserva la versión inicial;
2. entrega al LLM el código y los hallazgos SAST;
3. guarda la revisión;
4. solicita una versión corregida.

Después vuelve a ejecutar Semgrep sobre el código corregido con **exactamente la misma versión y reglas** usadas en el análisis inicial.

## 8. Estructura de evidencias

No sobrescribas respuestas. Conserva siempre:

- prompt;
- código original;
- metadata de la llamada;
- JSON de Semgrep;
- revisión LLM;
- código corregido;
- JSON de Semgrep posterior.

Esto permite construir después la Parte IV de resultados sin reconstruir manualmente el experimento.
