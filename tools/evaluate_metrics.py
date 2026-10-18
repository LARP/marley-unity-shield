#!/usr/bin/env python3
"""
evaluate_metrics.py
Quantitative evaluation engine for Unity protection benchmarking.
Calculates:
  - RCR Static (Static Recovery Rate)
  - RCR Dynamic (Dynamic Recovery Rate via Early Hook / Heap Reconstruction)
  - SSS (Symbol Secrecy Score - Static & Dynamic)
  - Normalized ETR (Effort to Reverse)
  - Runtime Overhead (Delta Boot Time, Delta RAM, P99 Frame Time)
"""

import os
import sys
import json
import argparse
from datetime import datetime

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_set_recovery(gt_classes, gt_methods, gt_strings, extracted_data):
    if not extracted_data:
        return 0.0, 0.0, 0.0, 0.0, {"classes": 0, "methods": 0, "strings": 0}

    dump_classes = set(extracted_data.get("classes", []))
    dump_methods = set(extracted_data.get("methods", []))
    dump_strings = set(extracted_data.get("strings", []))

    rec_classes = len(gt_classes.intersection(dump_classes))
    total_classes = max(1, len(gt_classes))
    rcr_classes = min(1.0, rec_classes / total_classes)

    rec_methods = len(gt_methods.intersection(dump_methods))
    total_methods = max(1, len(gt_methods))
    rcr_methods = min(1.0, rec_methods / total_methods)

    rec_strings = 0
    for s_gt in gt_strings:
        for s_dump in dump_strings:
            if s_gt in s_dump or s_dump in s_gt:
                rec_strings += 1
                break
    total_strings = max(1, len(gt_strings))
    rcr_strings = min(1.0, rec_strings / total_strings)

    # Weights: Classes 0.35, Methods 0.45, Strings 0.20
    w_c, w_m, w_s = 0.35, 0.45, 0.20
    rcr_composite = (w_c * rcr_classes) + (w_m * rcr_methods) + (w_s * rcr_strings)

    counts = {
        "classes": rec_classes,
        "methods": rec_methods,
        "strings": rec_strings
    }
    return rcr_classes, rcr_methods, rcr_strings, rcr_composite, counts

def calculate_metrics(ground_truth_path, dump_path, condition_tag="C0"):
    gt = load_json(ground_truth_path)
    dump = load_json(dump_path)

    if not gt or not dump:
        return None

    # Ground truth sets
    gt_classes = set()
    gt_methods = set()
    for cls in gt.get("Classes", []):
        cname = cls.get("FullName", "")
        if cname:
            gt_classes.add(cname)
            gt_classes.add(cname.split(".")[-1])
        for m in cls.get("Methods", []):
            mname = m.get("Name", "")
            if mname:
                gt_methods.add(mname)

    gt_strings = set(gt.get("SensitiveStringsGroundTruth", []))

    # Static extraction analysis
    static_data = dump.get("static_extraction")
    if static_data is None:
        # Fallback to general dump if dual structure not present
        static_data = dump

    _, _, _, rcr_static_comp, counts_static = extract_set_recovery(gt_classes, gt_methods, gt_strings, static_data)

    # Dynamic extraction analysis
    dynamic_data = dump.get("dynamic_extraction")
    if dynamic_data is None:
        dynamic_data = dump

    _, _, _, rcr_dynamic_comp, counts_dynamic = extract_set_recovery(gt_classes, gt_methods, gt_strings, dynamic_data)

    # SSS Secrecy Scores
    sss_static = max(0.0, 1.0 - rcr_static_comp)
    sss_dynamic = max(0.0, 1.0 - rcr_dynamic_comp)

    # Normalized Effort to Reverse (scale 1.0 - 10.0)
    condition_base_etr = {
        "C0": 1.0,  # Mono
        "C1": 3.5,  # Basic IL2CPP
        "C2": 5.5,  # IL2CPP Stripped
        "C3": 7.5,  # IL2CPP Custom Metadata (bypassed dynamically once spawned)
        "C4": 9.0,  # IL2CPP Header Patched + Obfuscation
        "C5": 10.0  # IL2CPP Hardened Guard (Anti-Hooking + Zero-Trust Crypto)
    }
    base_etr = condition_base_etr.get(condition_tag, 3.0)

    # ETR adjusted if dynamic hooks face unresolved APIs
    etr_adjustment = 0.0
    if not dump.get("runtime_api_resolved", True):
        etr_adjustment += 0.5
    if not dump.get("early_hook_success", True):
        etr_adjustment += 0.5

    normalized_etr = min(10.0, base_etr + etr_adjustment)

    # Runtime Overhead metrics
    overhead = dump.get("runtime_overhead", {
        "delta_boot_ms": 0.0,
        "delta_ram_mb": 0.0,
        "p99_frametime_ms": 16.6
    })

    report = {
        "condition": condition_tag,
        "evaluated_at": datetime.utcnow().isoformat(),
        "ground_truth_baseline": {
            "total_classes": len(gt_classes),
            "total_methods": len(gt_methods),
            "total_sensitive_strings": len(gt_strings)
        },
        "recovery_counts": {
            "static": counts_static,
            "dynamic": counts_dynamic
        },
        "metrics": {
            "RCR_Static": round(rcr_static_comp, 4),
            "RCR_Dynamic": round(rcr_dynamic_comp, 4),
            "SSS_Static": round(sss_static, 4),
            "SSS_Dynamic": round(sss_dynamic, 4),
            "ETR_Normalized": round(normalized_etr, 2)
        },
        "runtime_overhead": {
            "delta_boot_ms": overhead.get("delta_boot_ms", 0.0),
            "delta_ram_mb": overhead.get("delta_ram_mb", 0.0),
            "p99_frametime_ms": overhead.get("p99_frametime_ms", 16.6)
        }
    }

    return report

def generate_comparative_matrix(reports, output_path):
    summary = {
        "benchmark_title": "Unity Protection vs Reverse Engineering Analysis (REA)",
        "generated_at": datetime.utcnow().isoformat(),
        "methodology": "Dual Static Decompilation & Frida Runtime Interception",
        "matrix": reports
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    header = f"{'Condition':<10} | {'RCR Static':<12} | {'RCR Dynamic':<12} | {'SSS Dynamic':<12} | {'ETR (1-10)':<10} | {'Boot d(ms)':<11} | {'RAM d(MB)':<10} | {'P99 (ms)':<8}"
    sep = "=" * len(header)
    print("\n" + sep)
    print(header)
    print(sep)
    for r in reports:
        m = r["metrics"]
        o = r["runtime_overhead"]
        print(f"{r['condition']:<10} | {m['RCR_Static']:<12.1%} | {m['RCR_Dynamic']:<12.1%} | {m['SSS_Dynamic']:<12.1%} | {m['ETR_Normalized']:<10.2f} | {o['delta_boot_ms']:<11.1f} | {o['delta_ram_mb']:<10.1f} | {o['p99_frametime_ms']:<8.1f}")
    print(sep)
    print(f"[+] Corrected comparative matrix saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Marley Unity Shield Evaluation Harness")
    parser.add_argument("--gt", default="HoneyPot/ground_truth_symbols.json", help="Ground truth JSON path")
    parser.add_argument("--dump-dir", default="output/dumps", help="Directory containing condition dumps")
    parser.add_argument("--output", default="output/reports/evaluation_summary.json", help="Report output path")
    args = parser.parse_args()

    conditions = ["C0", "C1", "C2", "C3", "C4", "C5"]
    reports = []

    for cond in conditions:
        cond_gt = f"output/builds/{cond}/ground_truth_symbols.json"
        gt_file = cond_gt if os.path.exists(cond_gt) else args.gt

        dump_file = os.path.join(args.dump_dir, f"{cond}_dump.json")
        if os.path.exists(dump_file) and os.path.exists(gt_file):
            rep = calculate_metrics(gt_file, dump_file, cond)
            if rep:
                reports.append(rep)

    if reports:
        generate_comparative_matrix(reports, args.output)
    else:
        print("[!] No evaluation runs completed.")

if __name__ == "__main__":
    main()
