from pathlib import Path
import csv
import hashlib
import json
import random
import shutil

ROOT = Path(__file__).resolve().parents[1]

BENCHMARK = ROOT / "tools" / "benchmark-python"
EXPECTED = BENCHMARK / "expectedresults-0.1.csv"
TESTCODE = BENCHMARK / "testcode"

OUTPUT = ROOT / "data" / "block2" / "reference"
RESULTS = ROOT / "results" / "block2"

OUTPUT.mkdir(parents=True, exist_ok=True)
RESULTS.mkdir(parents=True, exist_ok=True)

SEED = 20260925
SAMPLES_PER_CWE = 5

TARGETS = {
    22: "Path Traversal",
    78: "Command Injection",
    79: "Cross-Site Scripting",
    89: "SQL Injection",
    330: "Weak Randomness",
    502: "Deserialization of Untrusted Data",
}

rng = random.Random(SEED)


def sha256_file(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(8192),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


# -------------------------------------------
# Leer ground truth
# -------------------------------------------

records = []

with EXPECTED.open(
    encoding="utf-8"
) as f:

    reader = csv.reader(f)

    for row in reader:

        if not row:
            continue

        if row[0].startswith("#"):
            continue

        if len(row) < 4:
            continue

        test_name = row[0].strip()
        category = row[1].strip()
        real_vulnerability = (
            row[2].strip().lower()
            == "true"
        )

        cwe = int(
            row[3].strip()
        )

        if (
            real_vulnerability
            and cwe in TARGETS
        ):

            records.append({
                "test_name":
                    test_name,
                "benchmark_category":
                    category,
                "cwe":
                    cwe,
            })


# -------------------------------------------
# Selección estratificada
# -------------------------------------------

selected = []

for cwe, description in TARGETS.items():

    candidates = [
        r for r in records
        if r["cwe"] == cwe
    ]

    print(
        f"CWE-{cwe}: "
        f"{len(candidates)} "
        f"casos vulnerables disponibles"
    )

    if len(candidates) < SAMPLES_PER_CWE:
        raise RuntimeError(
            f"No existen suficientes "
            f"casos para CWE-{cwe}"
        )

    chosen = rng.sample(
        candidates,
        SAMPLES_PER_CWE
    )

    chosen = sorted(
        chosen,
        key=lambda x: x["test_name"]
    )

    for index, record in enumerate(
        chosen,
        start=1
    ):

        test_name = record[
            "test_name"
        ]

        # Buscar el archivo sin asumir
        # estructura exacta del directorio.
        matches = list(
            TESTCODE.rglob(
                f"{test_name}.py"
            )
        )

        if len(matches) != 1:
            raise RuntimeError(
                f"{test_name}: "
                f"se encontraron "
                f"{len(matches)} archivos"
            )

        source = matches[0]

        sample_id = (
            f"B2_CWE{cwe}_{index:02d}"
        )

        destination = (
            OUTPUT
            / f"{sample_id}.py"
        )

        shutil.copy2(
            source,
            destination
        )

        metadata = {
            "sample_id":
                sample_id,

            "source":
                "OWASP Benchmark Python",

            "benchmark_version":
                "0.1",

            "benchmark_test_name":
                test_name,

            "benchmark_category":
                record[
                    "benchmark_category"
                ],

            "reference_cwe":
                f"CWE-{cwe}",

            "reference_description":
                description,

            "real_vulnerability":
                True,

            "selection_seed":
                SEED,

            "source_relative_path":
                str(
                    source.relative_to(
                        BENCHMARK
                    )
                ),

            "code_sha256":
                sha256_file(
                    destination
                ),
        }

        metadata_file = (
            OUTPUT
            / f"{sample_id}.json"
        )

        metadata_file.write_text(
            json.dumps(
                metadata,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        selected.append(
            metadata
        )


# -------------------------------------------
# Manifest
# -------------------------------------------

manifest = (
    RESULTS
    / "block2_dataset_manifest.json"
)

manifest.write_text(
    json.dumps(
        {
            "seed": SEED,
            "samples_per_cwe":
                SAMPLES_PER_CWE,
            "total_samples":
                len(selected),
            "samples":
                selected,
        },
        ensure_ascii=False,
        indent=2
    ),
    encoding="utf-8"
)


print()
print("=" * 60)
print("DATASET BLOQUE II PREPARADO")
print("=" * 60)
print(
    "Total muestras:",
    len(selected)
)
print(
    "Directorio:",
    OUTPUT
)
print(
    "Manifest:",
    manifest
)
print("=" * 60)