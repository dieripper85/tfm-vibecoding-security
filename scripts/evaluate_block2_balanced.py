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

SEMANTIC_TERMS = {
    "CWE-22": [
        "path traversal", "directory traversal", "ruta", "traversal",
    ],
    "CWE-78": [
        "command injection", "os command injection", "shell injection",
        "inyección de comandos",
    ],
    "CWE-79": [
        "cross-site scripting", "cross site scripting", "xss",
    ],
    "CWE-89": [
        "sql injection", "inyección sql",
    ],
    "CWE-330": [
        "weak randomness", "insufficient randomness", "insecure random",
        "predictable random", "weak random", "aleatoriedad débil",
        "aleatoriedad insegura", "predictable",
    ],
    "CWE-502": [
        "deserialization of untrusted data", "insecure deserialization",
        "unsafe deserialization", "deserialización insegura",
        "untrusted deserialization",
    ],
}

# Relaciones CWE jerárquicamente compatibles utilizadas en el experimento.
CWE_COMPATIBLE = {
    "CWE-330": {"CWE-338"},
}


def normalize_cwes(value):
    if value is None:
        return set()
    if isinstance(value, list):
        value = " ".join(map(str, value))
    return set(re.findall(r"CWE-\d+", str(value).upper()))


def vulnerability_text(vulnerability):
    fields = [
        vulnerability.get("type", ""),
        vulnerability.get("location", ""),
        vulnerability.get("explanation", ""),
        vulnerability.get("recommendation", ""),
    ]
    return " ".join(str(x) for x in fields if x is not None).lower()


def semantic_match(reference_cwe, vulnerability):
    text = vulnerability_text(vulnerability)
    return any(
        term.lower() in text
        for term in SEMANTIC_TERMS.get(reference_cwe, [])
    )


def pct(num, den):
    return round((num / den * 100), 2) if den else 0.0


sample_rows = []
reported_rows = []

by_cwe = defaultdict(lambda: {
    "samples": 0,
    "positives": 0,
    "negatives": 0,
    "tp": 0,
    "fp": 0,
    "tn": 0,
    "fn": 0,
    "exact_cwe": 0,
    "compatible_cwe": 0,
    "semantic_only": 0,
    "reported_vulnerabilities": 0,
    "additional_candidates": 0,
})

reference_files = sorted(REFERENCE_DIR.glob("B2_*.json"))

if not reference_files:
    raise RuntimeError(f"No se encontraron metadatos B2_*.json en {REFERENCE_DIR}")

for reference_file in reference_files:
    reference = json.loads(reference_file.read_text(encoding="utf-8"))

    sample_id = reference["sample_id"]
    reference_cwe = reference["reference_cwe"]
    real_vulnerability = bool(reference.get("real_vulnerability", False))
    sample_class = reference.get(
        "sample_class",
        "positive" if real_vulnerability else "negative",
    )

    review_file = REVIEWS_DIR / f"{sample_id}.json"
    if not review_file.exists():
        raise RuntimeError(f"Falta revisión para {sample_id}")

    review_data = json.loads(review_file.read_text(encoding="utf-8"))
    vulnerabilities = (
        review_data
        .get("review", {})
        .get("vulnerabilities", [])
    )

    if not isinstance(vulnerabilities, list):
        raise RuntimeError(
            f"{sample_id}: review.vulnerabilities no es una lista"
        )

    exact_matches = []
    compatible_matches = []
    semantic_matches = []

    for index, vulnerability in enumerate(vulnerabilities, start=1):
        model_cwes = normalize_cwes(vulnerability.get("cwe"))

        exact = reference_cwe in model_cwes
        compatible = bool(
            model_cwes & CWE_COMPATIBLE.get(reference_cwe, set())
        )
        semantic = semantic_match(reference_cwe, vulnerability)

        if exact:
            exact_matches.append(index)
        if compatible:
            compatible_matches.append(index)
        if semantic:
            semantic_matches.append(index)

        reported_rows.append({
            "sample_id": sample_id,
            "sample_class": sample_class,
            "real_vulnerability": int(real_vulnerability),
            "reference_cwe": reference_cwe,
            "finding_number": index,
            "model_type": vulnerability.get("type", ""),
            "model_cwe": vulnerability.get("cwe", ""),
            "model_severity": vulnerability.get("severity", ""),
            "exact_reference_cwe": int(exact),
            "compatible_reference_cwe": int(compatible),
            "semantic_reference_match": int(semantic),
            "location": vulnerability.get("location", ""),
            "explanation": vulnerability.get("explanation", ""),
        })

    target_detected = bool(
        exact_matches or compatible_matches or semantic_matches
    )
    exact_cwe = bool(exact_matches)
    compatible_cwe = bool(compatible_matches)

    if exact_cwe:
        detection_method = "EXACT_CWE"
    elif compatible_cwe:
        detection_method = "CWE_DESCENDANT"
    elif target_detected:
        detection_method = "SEMANTIC"
    else:
        detection_method = "NOT_DETECTED"

    if real_vulnerability and target_detected:
        classification = "TP"
    elif real_vulnerability and not target_detected:
        classification = "FN"
    elif (not real_vulnerability) and target_detected:
        classification = "FP"
    else:
        classification = "TN"

    # El benchmark etiqueta la vulnerabilidad objetivo de la muestra.
    # Hallazgos de otras categorías se conservan como candidatos adicionales,
    # pero no se convierten automáticamente en falsos positivos.
    additional_candidates = max(
        0,
        len(vulnerabilities) - (1 if target_detected else 0)
    )

    sample_rows.append({
        "sample_id": sample_id,
        "benchmark_test_name": reference["benchmark_test_name"],
        "sample_class": sample_class,
        "real_vulnerability": int(real_vulnerability),
        "reference_cwe": reference_cwe,
        "reference_description": reference.get("reference_description", ""),
        "reported_vulnerabilities": len(vulnerabilities),
        "target_detected": int(target_detected),
        "classification": classification,
        "exact_cwe_match": int(exact_cwe),
        "compatible_cwe_match": int(compatible_cwe),
        "detection_method": detection_method,
        "additional_finding_candidates": additional_candidates,
        "parse_error": review_data.get("parse_error", "") or "",
    })

    values = by_cwe[reference_cwe]
    values["samples"] += 1
    values["reported_vulnerabilities"] += len(vulnerabilities)
    values["additional_candidates"] += additional_candidates

    if real_vulnerability:
        values["positives"] += 1
    else:
        values["negatives"] += 1

    values[classification.lower()] += 1

    if real_vulnerability and classification == "TP":
        if exact_cwe:
            values["exact_cwe"] += 1
        elif compatible_cwe:
            values["compatible_cwe"] += 1
        elif target_detected:
            values["semantic_only"] += 1


# -----------------------------
# Validaciones del dataset
# -----------------------------
total_samples = len(sample_rows)
positives = sum(x["real_vulnerability"] for x in sample_rows)
negatives = total_samples - positives

if total_samples != 60:
    raise RuntimeError(
        f"Se esperaban 60 muestras balanceadas y se encontraron {total_samples}"
    )

if positives != 30 or negatives != 30:
    raise RuntimeError(
        f"Dataset no balanceado: positivas={positives}, negativas={negatives}"
    )


# -----------------------------
# Detalle por muestra
# -----------------------------
sample_file = RESULTS_DIR / "block2_balanced_sample_results.csv"

sample_fields = [
    "sample_id",
    "benchmark_test_name",
    "sample_class",
    "real_vulnerability",
    "reference_cwe",
    "reference_description",
    "reported_vulnerabilities",
    "target_detected",
    "classification",
    "exact_cwe_match",
    "compatible_cwe_match",
    "detection_method",
    "additional_finding_candidates",
    "parse_error",
]

with sample_file.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=sample_fields)
    writer.writeheader()
    writer.writerows(sample_rows)


# -----------------------------
# Hallazgos reportados
# -----------------------------
reported_file = RESULTS_DIR / "block2_balanced_reported_findings.csv"

reported_fields = [
    "sample_id",
    "sample_class",
    "real_vulnerability",
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

with reported_file.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=reported_fields)
    writer.writeheader()
    writer.writerows(reported_rows)


# -----------------------------
# Resumen por CWE
# -----------------------------
cwe_file = RESULTS_DIR / "block2_balanced_cwe_summary.csv"
cwe_fields = [
    "reference_cwe",
    "samples",
    "positives",
    "negatives",
    "tp",
    "fp",
    "tn",
    "fn",
    "precision_pct",
    "recall_pct",
    "specificity_pct",
    "accuracy_pct",
    "f1_pct",
    "exact_cwe_matches_over_tp",
    "compatible_cwe_matches_over_tp",
    "exact_cwe_accuracy_over_tp_pct",
    "exact_or_compatible_over_tp_pct",
    "reported_vulnerabilities",
    "additional_finding_candidates",
]

cwe_rows = []

for cwe, values in sorted(by_cwe.items()):
    tp = values["tp"]
    fp = values["fp"]
    tn = values["tn"]
    fn = values["fn"]

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0.0
    )

    exact = values["exact_cwe"]
    compatible = values["compatible_cwe"]

    cwe_rows.append({
        "reference_cwe": cwe,
        "samples": values["samples"],
        "positives": values["positives"],
        "negatives": values["negatives"],
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision_pct": round(precision * 100, 2),
        "recall_pct": round(recall * 100, 2),
        "specificity_pct": round(specificity * 100, 2),
        "accuracy_pct": round(accuracy * 100, 2),
        "f1_pct": round(f1 * 100, 2),
        "exact_cwe_matches_over_tp": exact,
        "compatible_cwe_matches_over_tp": compatible,
        "exact_cwe_accuracy_over_tp_pct": pct(exact, tp),
        "exact_or_compatible_over_tp_pct": pct(exact + compatible, tp),
        "reported_vulnerabilities": values["reported_vulnerabilities"],
        "additional_finding_candidates": values["additional_candidates"],
    })

with cwe_file.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=cwe_fields)
    writer.writeheader()
    writer.writerows(cwe_rows)


# -----------------------------
# Matriz de confusión global
# -----------------------------
tp = sum(1 for x in sample_rows if x["classification"] == "TP")
fp = sum(1 for x in sample_rows if x["classification"] == "FP")
tn = sum(1 for x in sample_rows if x["classification"] == "TN")
fn = sum(1 for x in sample_rows if x["classification"] == "FN")

precision = tp / (tp + fp) if (tp + fp) else 0.0
recall = tp / (tp + fn) if (tp + fn) else 0.0
specificity = tn / (tn + fp) if (tn + fp) else 0.0
accuracy = (tp + tn) / total_samples if total_samples else 0.0
f1 = (
    2 * precision * recall / (precision + recall)
    if (precision + recall) else 0.0
)

confusion_file = RESULTS_DIR / "block2_balanced_confusion_matrix.csv"
with confusion_file.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["metric", "value"]
    )
    writer.writeheader()
    for metric, value in [
        ("TP", tp),
        ("FP", fp),
        ("TN", tn),
        ("FN", fn),
    ]:
        writer.writerow({"metric": metric, "value": value})


# -----------------------------
# Resumen global
# -----------------------------
exact_total = sum(
    x["exact_cwe_match"]
    for x in sample_rows
    if x["classification"] == "TP"
)
compatible_total = sum(
    x["compatible_cwe_match"]
    for x in sample_rows
    if x["classification"] == "TP"
)
additional_total = sum(
    x["additional_finding_candidates"]
    for x in sample_rows
)

global_file = RESULTS_DIR / "block2_balanced_global_summary.csv"

global_fields = [
    "samples",
    "positives",
    "negatives",
    "tp",
    "fp",
    "tn",
    "fn",
    "precision_pct",
    "recall_pct",
    "specificity_pct",
    "accuracy_pct",
    "f1_pct",
    "exact_cwe_matches_over_tp",
    "compatible_cwe_matches_over_tp",
    "exact_cwe_accuracy_over_tp_pct",
    "exact_or_compatible_over_tp_pct",
    "additional_finding_candidates",
]

global_row = {
    "samples": total_samples,
    "positives": positives,
    "negatives": negatives,
    "tp": tp,
    "fp": fp,
    "tn": tn,
    "fn": fn,
    "precision_pct": round(precision * 100, 2),
    "recall_pct": round(recall * 100, 2),
    "specificity_pct": round(specificity * 100, 2),
    "accuracy_pct": round(accuracy * 100, 2),
    "f1_pct": round(f1 * 100, 2),
    "exact_cwe_matches_over_tp": exact_total,
    "compatible_cwe_matches_over_tp": compatible_total,
    "exact_cwe_accuracy_over_tp_pct": pct(exact_total, tp),
    "exact_or_compatible_over_tp_pct": pct(
        exact_total + compatible_total,
        tp,
    ),
    "additional_finding_candidates": additional_total,
}

with global_file.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=global_fields)
    writer.writeheader()
    writer.writerow(global_row)


print("=" * 64)
print("EVALUACION BLOQUE II BALANCEADO FINALIZADA")
print("=" * 64)
print("Muestras        :", total_samples)
print("Positivas       :", positives)
print("Negativas       :", negatives)
print("TP              :", tp)
print("FP              :", fp)
print("TN              :", tn)
print("FN              :", fn)
print("Precision       :", f"{global_row['precision_pct']}%")
print("Recall          :", f"{global_row['recall_pct']}%")
print("Especificidad   :", f"{global_row['specificity_pct']}%")
print("Exactitud       :", f"{global_row['accuracy_pct']}%")
print("F1              :", f"{global_row['f1_pct']}%")
print(
    "CWE exacta/TP   :",
    f"{global_row['exact_cwe_accuracy_over_tp_pct']}%"
)
print(
    "CWE exacta+comp.:",
    f"{global_row['exact_or_compatible_over_tp_pct']}%"
)
print("Resultados en   :", RESULTS_DIR)
print("=" * 64)
