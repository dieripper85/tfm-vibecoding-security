from pathlib import Path
from collections import defaultdict
import csv
import json
import re

ROOT = Path(__file__).resolve().parents[1]

REFERENCE_DIR = ROOT / "data" / "block2" / "reference"
REVIEWS_DIR = ROOT / "data" / "block2" / "reviews"
RESULTS_DIR = ROOT / "results" / "block2"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Palabras utilizadas únicamente para determinar si el modelo
# reconoció conceptualmente la vulnerabilidad cuando no indicó
# correctamente la CWE.
SEMANTIC_TERMS = {
    "CWE-22": [
        "path traversal",
        "directory traversal",
        "ruta",
        "traversal",
    ],
    "CWE-78": [
        "command injection",
        "os command injection",
        "shell injection",
        "inyección de comandos",
    ],
    "CWE-79": [
        "cross-site scripting",
        "cross site scripting",
        "xss",
    ],
    "CWE-89": [
        "sql injection",
        "inyección sql",
    ],
    "CWE-330": [
        "weak randomness",
        "insufficient randomness",
        "insecure random",
        "predictable random",
        "weak random",
        "aleatoriedad débil",
        "aleatoriedad insegura",
        "predictable",
    ],
    "CWE-502": [
        "deserialization of untrusted data",
        "insecure deserialization",
        "unsafe deserialization",
        "deserialización insegura",
        "untrusted deserialization",
    ],
}

# Relaciones CWE jerárquicamente compatibles.
CWE_COMPATIBLE = {
    "CWE-330": {"CWE-338"}
}


def normalize_cwes(value):
    """
    Extrae CWE-NNN de cualquier texto que haya generado el modelo.
    """

    if value is None:
        return set()

    if isinstance(value, list):
        value = " ".join(map(str, value))

    return set(
        re.findall(
            r"CWE-\d+",
            str(value).upper()
        )
    )


def vulnerability_text(vulnerability):
    """
    Une los campos descriptivos para la detección semántica.
    """

    fields = [
        vulnerability.get("type", ""),
        vulnerability.get("location", ""),
        vulnerability.get("explanation", ""),
        vulnerability.get("recommendation", ""),
    ]

    return " ".join(
        str(x) for x in fields
        if x is not None
    ).lower()


def semantic_match(reference_cwe, vulnerability):

    text = vulnerability_text(
        vulnerability
    )

    terms = SEMANTIC_TERMS[
        reference_cwe
    ]

    return any(
        term.lower() in text
        for term in terms
    )


sample_rows = []
reported_rows = []

by_cwe = defaultdict(
    lambda: {
        "samples": 0,
        "detected": 0,
        "omitted": 0,
        "exact_cwe": 0,
        "compatible_cwe": 0,
        "reported_vulnerabilities": 0,
        "additional_candidates": 0,
    }
)

reference_files = sorted(
    REFERENCE_DIR.glob(
        "B2_*.json"
    )
)

for reference_file in reference_files:

    reference = json.loads(
        reference_file.read_text(
            encoding="utf-8"
        )
    )

    sample_id = reference[
        "sample_id"
    ]

    reference_cwe = reference[
        "reference_cwe"
    ]

    review_file = (
        REVIEWS_DIR
        / f"{sample_id}.json"
    )

    if not review_file.exists():
        raise RuntimeError(
            f"Falta revisión para "
            f"{sample_id}"
        )

    review_data = json.loads(
        review_file.read_text(
            encoding="utf-8"
        )
    )

    vulnerabilities = (
        review_data
        .get("review", {})
        .get("vulnerabilities", [])
    )

    exact_matches = []
    compatible_matches = []
    semantic_matches = []

    for index, vulnerability in enumerate(
        vulnerabilities,
        start=1
    ):

        model_cwes = normalize_cwes(
            vulnerability.get(
                "cwe"
            )
        )

        exact = (
            reference_cwe
            in model_cwes
        )

        compatible = bool(
            model_cwes
            & CWE_COMPATIBLE.get(reference_cwe, set())
        )

        semantic = semantic_match(
            reference_cwe,
            vulnerability
        )

        if exact:
            exact_matches.append(index)

        if compatible:
            compatible_matches.append(index)

        if semantic:
            semantic_matches.append(index)

        reported_rows.append({
            "sample_id":
                sample_id,

            "reference_cwe":
                reference_cwe,

            "finding_number":
                index,

            "model_type":
                vulnerability.get(
                    "type",
                    ""
                ),

            "model_cwe":
                vulnerability.get(
                    "cwe",
                    ""
                ),

            "model_severity":
                vulnerability.get(
                    "severity",
                    ""
                ),

            "exact_reference_cwe":
                int(exact),

            "compatible_reference_cwe":
                int(compatible),

            "semantic_reference_match":
                int(semantic),

            "location":
                vulnerability.get(
                    "location",
                    ""
                ),

            "explanation":
                vulnerability.get(
                    "explanation",
                    ""
                ),
        })

    # Detección de la vulnerabilidad:
    # exacta por CWE o reconocida semánticamente.
    detected = bool(
        exact_matches
        or compatible_matches
        or semantic_matches
    )

    exact_cwe = bool(
        exact_matches
    )

    compatible_cwe = bool(
        compatible_matches
    )

    omitted = not detected

    # Ground truth contiene una vulnerabilidad de referencia.
    # Todo hallazgo adicional queda como candidato,
    # NO como falso positivo automático.
    additional_candidates = max(
        0,
        len(vulnerabilities)
        - (1 if detected else 0)
    )

    detection_method = ""

    if exact_cwe:
        detection_method = "EXACT_CWE"

    elif compatible_cwe:
        detection_method = "CWE_DESCENDANT"

    elif detected:
        detection_method = "SEMANTIC"

    else:
        detection_method = "NOT_DETECTED"

    sample_rows.append({
        "sample_id":
            sample_id,

        "benchmark_test_name":
            reference[
                "benchmark_test_name"
            ],

        "reference_cwe":
            reference_cwe,

        "reference_description":
            reference[
                "reference_description"
            ],

        "reported_vulnerabilities":
            len(vulnerabilities),

        "reference_detected":
            int(detected),

        "reference_omitted":
            int(omitted),

        "exact_cwe_match":
            int(exact_cwe),

        "compatible_cwe_match":
            int(compatible_cwe),

        "detection_method":
            detection_method,

        "additional_finding_candidates":
            additional_candidates,

        "parse_error":
            review_data.get(
                "parse_error",
                ""
            ) or "",
    })

    values = by_cwe[
        reference_cwe
    ]

    values["samples"] += 1

    values[
        "reported_vulnerabilities"
    ] += len(vulnerabilities)

    values[
        "additional_candidates"
    ] += additional_candidates

    if detected:
        values["detected"] += 1
    else:
        values["omitted"] += 1

    if exact_cwe:
        values["exact_cwe"] += 1

    if compatible_cwe:
        values["compatible_cwe"] += 1


# --------------------------------------------------
# DETALLE POR MUESTRA
# --------------------------------------------------

sample_file = (
    RESULTS_DIR
    / "block2_sample_results.csv"
)

sample_fields = [
    "sample_id",
    "benchmark_test_name",
    "reference_cwe",
    "reference_description",
    "reported_vulnerabilities",
    "reference_detected",
    "reference_omitted",
    "exact_cwe_match",
    "compatible_cwe_match",
    "detection_method",
    "additional_finding_candidates",
    "parse_error",
]

with sample_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=sample_fields
    )

    writer.writeheader()
    writer.writerows(sample_rows)


# --------------------------------------------------
# TODOS LOS HALLAZGOS REPORTADOS POR EL MODELO
# --------------------------------------------------

reported_file = (
    RESULTS_DIR
    / "block2_reported_findings.csv"
)

reported_fields = [
    "sample_id",
    "reference_cwe",
    "finding_number",
    "model_type",
    "model_cwe",
    "model_severity",
    "exact_reference_cwe",
    "compatible_reference_cwe",
    "semantic_reference_match",
    "location",
    "explanation",
]

with reported_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=reported_fields
    )

    writer.writeheader()
    writer.writerows(reported_rows)


# --------------------------------------------------
# RESUMEN POR CWE
# --------------------------------------------------

cwe_file = (
    RESULTS_DIR
    / "block2_cwe_summary.csv"
)

cwe_fields = [
    "reference_cwe",
    "samples",
    "detected",
    "detection_rate_pct",
    "omitted",
    "omission_rate_pct",
    "exact_cwe_matches",
    "compatible_cwe_matches",
    "cwe_accuracy_over_detected_pct",
    "reported_vulnerabilities",
    "additional_finding_candidates",
]

cwe_rows = []

for cwe, values in sorted(
    by_cwe.items()
):

    detected = values["detected"]
    samples = values["samples"]
    exact = values["exact_cwe"]

    cwe_rows.append({
        "reference_cwe":
            cwe,

        "samples":
            samples,

        "detected":
            detected,

        "detection_rate_pct":
            round(
                detected
                / samples
                * 100,
                2
            ),

        "omitted":
            values["omitted"],

        "omission_rate_pct":
            round(
                values["omitted"]
                / samples
                * 100,
                2
            ),

        "exact_cwe_matches":
            exact,

        "compatible_cwe_matches":
            values["compatible_cwe"],

        "cwe_accuracy_over_detected_pct":
            round(
                exact
                / detected
                * 100,
                2
            )
            if detected else 0,

        "reported_vulnerabilities":
            values[
                "reported_vulnerabilities"
            ],

        "additional_finding_candidates":
            values[
                "additional_candidates"
            ],
    })


with cwe_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=cwe_fields
    )

    writer.writeheader()
    writer.writerows(cwe_rows)


# --------------------------------------------------
# RESUMEN GLOBAL
# --------------------------------------------------

total_samples = len(sample_rows)

detected_total = sum(
    x["reference_detected"]
    for x in sample_rows
)

omitted_total = sum(
    x["reference_omitted"]
    for x in sample_rows
)

exact_total = sum(
    x["exact_cwe_match"]
    for x in sample_rows
)

compatible_total = sum(
    x["compatible_cwe_match"]
    for x in sample_rows
)

additional_total = sum(
    x[
        "additional_finding_candidates"
    ]
    for x in sample_rows
)

global_file = (
    RESULTS_DIR
    / "block2_global_summary.csv"
)

global_fields = [
    "samples",
    "detected",
    "detection_rate_pct",
    "omitted",
    "omission_rate_pct",
    "exact_cwe_matches",
    "compatible_cwe_matches",
    "cwe_accuracy_over_detected_pct",
    "additional_finding_candidates",
]

global_row = {
    "samples":
        total_samples,

    "detected":
        detected_total,

    "detection_rate_pct":
        round(
            detected_total
            / total_samples
            * 100,
            2
        ),

    "omitted":
        omitted_total,

    "omission_rate_pct":
        round(
            omitted_total
            / total_samples
            * 100,
            2
        ),

    "exact_cwe_matches":
        exact_total,

    "compatible_cwe_matches":
        compatible_total,

    "cwe_accuracy_over_detected_pct":
        round(
            exact_total
            / detected_total
            * 100,
            2
        )
        if detected_total else 0,

    "additional_finding_candidates":
        additional_total,
}

with global_file.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=global_fields
    )

    writer.writeheader()
    writer.writerow(global_row)


print("=" * 60)
print("EVALUACION BLOQUE II FINALIZADA")
print("=" * 60)
print("Muestras              :", total_samples)
print("Detectadas             :", detected_total)
print("Omitidas               :", omitted_total)
print("CWE exactas            :", exact_total)
print("CWE compatibles        :", compatible_total)
print(
    "Deteccion global       :",
    f"{global_row['detection_rate_pct']}%"
)
print(
    "Exactitud CWE/detectada:",
    f"{global_row['cwe_accuracy_over_detected_pct']}%"
)
print(
    "Hallazgos adicionales :",
    additional_total
)
print("=" * 60)