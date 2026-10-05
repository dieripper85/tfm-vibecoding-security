from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import shutil
import subprocess
from pathlib import Path

SEED = 20260925
SAMPLES_PER_CLASS_PER_CWE = 5
EXPECTED_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"

TARGETS = {
    22:  ("pathtraver", "Path Traversal"),
    78:  ("cmdi", "Command Injection"),
    79:  ("xss", "Cross-Site Scripting"),
    89:  ("sqli", "SQL Injection"),
    330: ("weakrand", "Weak Randomness"),
    502: ("deserialization", "Deserialization of Untrusted Data"),
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_benchmark_dir(project_root: Path, supplied: str | None) -> Path:
    if supplied:
        p = Path(supplied).expanduser().resolve()
        if not (p / "expectedresults-0.1.csv").exists():
            raise FileNotFoundError(f"No existe expectedresults-0.1.csv en {p}")
        return p

    candidates = [
        project_root / "tools" / "BenchmarkPython",
        project_root / "tools" / "benchmark-python",
        project_root / "tools" / "benchmark_python",
        project_root / "BenchmarkPython",
    ]
    for p in candidates:
        if (p / "expectedresults-0.1.csv").exists():
            return p.resolve()

    found = list((project_root / "tools").glob("**/expectedresults-0.1.csv")) if (project_root / "tools").exists() else []
    if len(found) == 1:
        return found[0].parent.resolve()
    if len(found) > 1:
        raise RuntimeError("Se encontraron varios expectedresults-0.1.csv; usa --benchmark-dir.")
    raise FileNotFoundError("No se encontró OWASP Benchmark Python. Usa --benchmark-dir.")


def git_commit(repo: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return None


def load_expected_results(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = next(csv.reader([raw]))
            if len(parts) < 4:
                continue
            test_name, category, real, cwe = [x.strip() for x in parts[:4]]
            rows.append(
                {
                    "test_name": test_name,
                    "category": category,
                    "real_vulnerability": real.lower() == "true",
                    "cwe": int(cwe),
                }
            )
    return rows


def load_existing_positives(reference_dir: Path) -> list[dict]:
    positives = []
    for meta_path in sorted(reference_dir.glob("B2_CWE*.json")):
        # Excluir las nuevas negativas si el script se reejecuta.
        if "_NV_" in meta_path.stem:
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if meta.get("real_vulnerability") is True:
            positives.append(meta)
    return positives


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Amplía Bloque II a 30 positivas + 30 negativas del mismo OWASP Benchmark Python."
    )
    parser.add_argument("--project-root", default=".", help="Raíz del laboratorio TFM")
    parser.add_argument("--benchmark-dir", default=None, help="Ruta a OWASP BenchmarkPython")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    root = Path(args.project_root).expanduser().resolve()
    benchmark = find_benchmark_dir(root, args.benchmark_dir)
    expected_file = benchmark / "expectedresults-0.1.csv"
    testcode_dir = benchmark / "testcode"
    reference_dir = root / "data" / "block2" / "reference"
    results_dir = root / "results" / "block2"
    reference_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Project root : {root}")
    print(f"[INFO] Benchmark    : {benchmark}")

    commit = git_commit(benchmark)
    if commit:
        print(f"[INFO] Benchmark commit: {commit}")
        if commit != EXPECTED_COMMIT:
            print(
                f"[WARN] El commit no coincide con el usado originalmente ({EXPECTED_COMMIT}). "
                "Para máxima reproducibilidad conviene usar exactamente ese commit."
            )
    else:
        print("[WARN] No se pudo verificar el commit Git del benchmark.")

    rows = load_expected_results(expected_file)
    positives = load_existing_positives(reference_dir)

    # Validar que conservamos exactamente las 30 positivas originales.
    positive_by_cwe: dict[int, list[dict]] = {cwe: [] for cwe in TARGETS}
    for meta in positives:
        try:
            cwe_num = int(str(meta["reference_cwe"]).replace("CWE-", ""))
        except Exception:
            continue
        if cwe_num in positive_by_cwe:
            positive_by_cwe[cwe_num].append(meta)

    for cwe, metas in positive_by_cwe.items():
        if len(metas) != SAMPLES_PER_CLASS_PER_CWE:
            raise RuntimeError(
                f"CWE-{cwe}: esperaba {SAMPLES_PER_CLASS_PER_CWE} positivas originales, encontré {len(metas)}. "
                "No continúo para no alterar la trazabilidad."
            )

    selected_negatives = []
    for cwe, (category, description) in TARGETS.items():
        candidates = [
            r for r in rows
            if r["cwe"] == cwe
            and r["category"] == category
            and r["real_vulnerability"] is False
        ]
        if len(candidates) < SAMPLES_PER_CLASS_PER_CWE:
            raise RuntimeError(
                f"CWE-{cwe}: solo hay {len(candidates)} negativas disponibles; se requieren {SAMPLES_PER_CLASS_PER_CWE}."
            )

        rng = random.Random(f"{args.seed}:CWE-{cwe}:NV")
        chosen = rng.sample(sorted(candidates, key=lambda x: x["test_name"]), SAMPLES_PER_CLASS_PER_CWE)
        chosen = sorted(chosen, key=lambda x: x["test_name"])

        for i, row in enumerate(chosen, 1):
            sample_id = f"B2_CWE{cwe}_NV_{i:02d}"
            src = testcode_dir / f"{row['test_name']}.py"
            if not src.exists():
                raise FileNotFoundError(f"No existe el código de benchmark: {src}")

            dst_py = reference_dir / f"{sample_id}.py"
            dst_json = reference_dir / f"{sample_id}.json"
            shutil.copy2(src, dst_py)

            meta = {
                "sample_id": sample_id,
                "source": "OWASP Benchmark Python",
                "benchmark_version": "0.1",
                "benchmark_test_name": row["test_name"],
                "benchmark_category": row["category"],
                "reference_cwe": f"CWE-{cwe}",
                "reference_description": description,
                "real_vulnerability": False,
                "sample_class": "negative",
                "selection_seed": args.seed,
                "selection_strategy": "5 non-vulnerable samples per CWE, deterministic sampling",
                "source_relative_path": str(Path("testcode") / f"{row['test_name']}.py"),
                "code_sha256": sha256_file(dst_py),
            }
            dst_json.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
            selected_negatives.append(meta)

    # Armar manifiesto balanceado sin renombrar las positivas existentes.
    manifest_samples = []
    for cwe in TARGETS:
        for meta in sorted(positive_by_cwe[cwe], key=lambda x: x["sample_id"]):
            m = dict(meta)
            m["sample_class"] = "positive"
            manifest_samples.append(m)
        manifest_samples.extend(
            sorted(
                [m for m in selected_negatives if m["reference_cwe"] == f"CWE-{cwe}"],
                key=lambda x: x["sample_id"],
            )
        )

    manifest = {
        "seed": args.seed,
        "benchmark_version": "0.1",
        "benchmark_commit_expected": EXPECTED_COMMIT,
        "benchmark_commit_observed": commit,
        "positive_samples_reused": 30,
        "negative_samples_added": 30,
        "total_samples": 60,
        "samples_per_cwe_per_class": SAMPLES_PER_CLASS_PER_CWE,
        "target_cwes": [f"CWE-{cwe}" for cwe in TARGETS],
        "samples": manifest_samples,
    }

    manifest_json = results_dir / "block2_dataset_manifest_balanced.json"
    manifest_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    manifest_csv = results_dir / "block2_dataset_manifest_balanced.csv"
    fields = [
        "sample_id", "sample_class", "benchmark_test_name", "benchmark_category",
        "reference_cwe", "reference_description", "real_vulnerability",
        "selection_seed", "source_relative_path", "code_sha256",
    ]
    with manifest_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for m in manifest_samples:
            w.writerow({k: m.get(k, "") for k in fields})

    print("\n[OK] Dataset balanceado preparado.")
    print("     Positivas conservadas : 30")
    print("     Negativas añadidas    : 30")
    print("     Total                  : 60")
    print(f"[OK] Manifiesto JSON: {manifest_json}")
    print(f"[OK] Manifiesto CSV : {manifest_csv}")
    print("\nNegativas seleccionadas:")
    for m in selected_negatives:
        print(f"  {m['sample_id']} <- {m['benchmark_test_name']} ({m['reference_cwe']})")


if __name__ == "__main__":
    main()
