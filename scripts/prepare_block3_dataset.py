from pathlib import Path
from collections import defaultdict
import csv
import hashlib
import json
import shutil


ROOT = Path(__file__).resolve().parents[1]

B1_FINDINGS = (
    ROOT
    / "results"
    / "block1"
    / "block1_findings_classified.csv"
)

B1_GENERATED = (
    ROOT
    / "data"
    / "block1"
    / "generated"
)

B3_SOURCE = (
    ROOT
    / "data"
    / "block3"
    / "source"
)

B3_RESULTS = (
    ROOT
    / "results"
    / "block3"
)

B3_SOURCE.mkdir(
    parents=True,
    exist_ok=True
)

B3_RESULTS.mkdir(
    parents=True,
    exist_ok=True
)


def sha256_file(path):

    h = hashlib.sha256()

    with path.open("rb") as f:

        for chunk in iter(
            lambda: f.read(8192),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


# --------------------------------------------------
# Leer hallazgos del Bloque I
# --------------------------------------------------

with B1_FINDINGS.open(
    encoding="utf-8-sig"
) as f:

    reader = csv.DictReader(f)

    rows = [
        row
        for row in reader
        if row.get(
            "scope",
            ""
        ).strip().upper()
        == "SECURITY"
    ]


if not rows:
    raise RuntimeError(
        "No se encontraron "
        "hallazgos SECURITY "
        "del Bloque I."
    )


# --------------------------------------------------
# Agrupar por muestra
# --------------------------------------------------

by_sample = defaultdict(list)

for row in rows:

    sample_id = row.get(
        "sample_id",
        ""
    ).strip()

    if not sample_id:
        raise RuntimeError(
            "Existe un hallazgo "
            "sin sample_id."
        )

    by_sample[sample_id].append(
        row
    )


print("=" * 60)
print("PREPARACION BLOQUE III")
print("=" * 60)

print(
    "Hallazgos SECURITY PRE:",
    len(rows)
)

print(
    "Muestras afectadas:",
    len(by_sample)
)


manifest_rows = []


# --------------------------------------------------
# Crear dataset PRE del Bloque III
# --------------------------------------------------

for sample_id in sorted(
    by_sample
):

    findings = by_sample[
        sample_id
    ]

    # Buscar código original sin asumir
    # subdirectorios concretos.
    matches = list(
        B1_GENERATED.rglob(
            f"{sample_id}.py"
        )
    )

    if len(matches) != 1:

        raise RuntimeError(
            f"{sample_id}: "
            f"se encontraron "
            f"{len(matches)} "
            f"archivos Python."
        )

    source_file = matches[0]

    destination = (
        B3_SOURCE
        / f"{sample_id}.py"
    )

    shutil.copy2(
        source_file,
        destination
    )

    first = findings[0]

    scenario = (
        first.get(
            "scenario",
            ""
        ).strip()
    )

    condition = (
        first.get(
            "condition",
            ""
        ).strip()
    )

    # Fallback por si las columnas
    # no estuvieran presentes.
    parts = sample_id.split("_")

    if not scenario and len(parts) >= 4:
        scenario = parts[1]

    if not condition and len(parts) >= 4:
        condition = parts[2]

    cwes = sorted({
        row.get(
            "cwe",
            ""
        ).strip()
        for row in findings
        if row.get(
            "cwe",
            ""
        ).strip()
    })

    manifest_rows.append({
        "sample_id":
            sample_id,

        "scenario":
            scenario,

        "condition":
            condition,

        "pre_security_raw_findings":
            len(findings),

        "pre_unique_cwes":
            " | ".join(cwes),

        "pre_unique_cwe_count":
            len(cwes),

        "source_sha256":
            sha256_file(
                destination
            ),
    })


# --------------------------------------------------
# CSV
# --------------------------------------------------

manifest_csv = (
    B3_RESULTS
    / "block3_manifest.csv"
)

fields = [
    "sample_id",
    "scenario",
    "condition",
    "pre_security_raw_findings",
    "pre_unique_cwes",
    "pre_unique_cwe_count",
    "source_sha256",
]

with manifest_csv.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(
        manifest_rows
    )


# --------------------------------------------------
# JSON
# --------------------------------------------------

manifest_json = (
    B3_RESULTS
    / "block3_manifest.json"
)

manifest_json.write_text(
    json.dumps(
        {
            "source":
                "Block I security findings",

            "selection":
                "All samples with at least "
                "one SECURITY finding",

            "total_samples":
                len(manifest_rows),

            "samples":
                manifest_rows,
        },
        ensure_ascii=False,
        indent=2
    ),
    encoding="utf-8"
)


print()
print("=" * 60)
print("DATASET BLOQUE III PREPARADO")
print("=" * 60)

print(
    "Muestras:",
    len(manifest_rows)
)

print(
    "Código fuente:",
    B3_SOURCE
)

print(
    "Manifest:",
    manifest_csv
)

print("=" * 60)