#!/usr/bin/env python3
"""
frida_early_hook_dump.py
Dynamic instrumentation harness using Frida to perform early suspension and hook injection
at il2cpp_init or module load time. Intercepts runtime exports (il2cpp_domain_get_assemblies,
il2cpp_class_from_name), scans post-initialization heap, and handles anti-hooking/integrity guards.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

def run_frida_spawn_hook(target_exe, script_path, output_dump_path, timeout_sec=15):
    if not FRIDA_AVAILABLE:
        print("[!] Frida library is not installed in the current Python environment.")
        return False

    if not os.path.exists(target_exe):
        print(f"[ERROR] Target executable not found: {target_exe}")
        return False

    dump_result = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": target_exe,
        "static_extraction": {
            "classes": [],
            "methods": [],
            "strings": []
        },
        "dynamic_extraction": {
            "classes": [],
            "methods": [],
            "strings": []
        },
        "metadata_detected": False,
        "early_hook_success": False,
        "runtime_api_resolved": False,
        "heap_scan_completed": False,
        "anti_hook_detected": False,
        "dump_blocked": False
    }

    device = frida.get_local_device()
    print(f"[*] Spawning process in suspended state: {target_exe}")
    pid = device.spawn([target_exe])
    print(f"[*] Process spawned with PID: {pid}. Attaching session...")

    session = device.attach(pid)

    with open(script_path, "r", encoding="utf-8") as f:
        script_code = f.read()

    script = session.create_script(script_code)
    completed = False

    def on_message(message, data):
        nonlocal completed
        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")
            if msg_type == "HOOK_HIT":
                print(f"[FRIDA EVENT] Early Hook hit: {payload.get('event')} (RVA: {payload.get('rva')})")
                dump_result["early_hook_success"] = True
            elif msg_type == "HOOK_BLOCKED":
                print(f"[FRIDA EVENT] [DEFENSE TRIGGERED] Hook blocked: {payload.get('reason')}")
                dump_result["early_hook_success"] = False
                dump_result["anti_hook_detected"] = True
                dump_result["dump_blocked"] = True
                completed = True
            elif msg_type == "DUMP_COMPLETED":
                data = payload.get("data", {})
                dump_result["dynamic_extraction"]["classes"] = data.get("classes", [])
                dump_result["dynamic_extraction"]["methods"] = data.get("methods", [])
                dump_result["dynamic_extraction"]["strings"] = data.get("strings", [])
                dump_result["runtime_api_resolved"] = data.get("runtimeApiResolved", False)
                dump_result["heap_scan_completed"] = data.get("extractedFromHeap", False)
                dump_result["anti_hook_detected"] = data.get("antiHookDetected", False)
                dump_result["dump_blocked"] = data.get("dumpBlocked", False)
                dump_result["metadata_detected"] = data.get("metadataHeader") is not None
                print(f"[FRIDA EVENT] Dynamic extraction completed: {len(dump_result['dynamic_extraction']['classes'])} classes, {len(dump_result['dynamic_extraction']['methods'])} methods.")
                completed = True
        elif message["type"] == "error":
            print(f"[FRIDA ERROR] {message.get('description')}")

    script.on("message", on_message)
    script.load()

    print("[*] Resuming process execution...")
    device.resume(pid)

    start_time = time.time()
    while not completed and (time.time() - start_time) < timeout_sec:
        time.sleep(0.5)

    try:
        session.detach()
        device.kill(pid)
    except Exception:
        pass

    os.makedirs(os.path.dirname(output_dump_path), exist_ok=True)
    with open(output_dump_path, "w", encoding="utf-8") as f:
        json.dump(dump_result, f, indent=2)

    print(f"[+] Dump report saved to {output_dump_path}")
    return True

def mock_dynamic_dump(condition, output_dump_path):
    """
    Simulates both static and dynamic dumps across C0 to C5.
    Demonstrates:
    - C0-C2: Direct recovery in static/dynamic
    - C3-C4: False positive of static encryption neutralized by dynamic Frida hook
    - C5: Hardened NativeIntegrityGuard + Zero-Trust crypto completely blocks runtime hooking
          and prevents memory scraping of ephemeral secrets.
    """
    os.makedirs(os.path.dirname(output_dump_path), exist_ok=True)

    # Ground truth reference sets for simulation
    all_classes = ["HoneyPot.Core.CombatFormula", "HoneyPot.Security.SecurityVault", "HoneyPot.Config.GameBalanceConfig"]
    all_methods = ["CalculateMitigatedDamage", "SettleEncounterReward", "ValidateClientSignature", "GetInternalSeed"]
    all_strings = [
        "https://telemetry.anticheat.internal.example.org/v2/handshake",
        "k7!9F#vP$2mZ&9qL*8sB4wE@1nC%5yD^",
        "RAE_EXPERIMENT_SECURITY_SALT_TOKEN_99812",
        "SHA256_SIG_BALANCE_908123"
    ]

    # Concrete scenario definitions (Static vs Dynamic)
    scenario_profiles = {
        "C0": { # Mono: Fully decompilable statically & dynamically
            "static": { "classes": all_classes, "methods": all_methods, "strings": all_strings },
            "dynamic": { "classes": all_classes, "methods": all_methods, "strings": all_strings },
            "runtime_overhead": { "delta_boot_ms": 0.0, "delta_ram_mb": 0.0, "p99_frametime_ms": 16.6 },
            "early_hook_success": True,
            "runtime_api_resolved": True,
            "heap_scan_completed": True,
            "anti_hook_detected": False,
            "dump_blocked": False
        },
        "C1": { # IL2CPP Basic: Standard metadata on disk
            "static": { "classes": all_classes[:2], "methods": all_methods[:3], "strings": all_strings[:3] },
            "dynamic": { "classes": all_classes, "methods": all_methods[:3], "strings": all_strings[:3] },
            "runtime_overhead": { "delta_boot_ms": 35.0, "delta_ram_mb": 12.5, "p99_frametime_ms": 16.7 },
            "early_hook_success": True,
            "runtime_api_resolved": True,
            "heap_scan_completed": True,
            "anti_hook_detected": False,
            "dump_blocked": False
        },
        "C2": { # IL2CPP Stripped: Names stripped from static tables
            "static": { "classes": [all_classes[0]], "methods": [all_methods[0]], "strings": [all_strings[0]] },
            "dynamic": { "classes": all_classes[:2], "methods": all_methods[:2], "strings": all_strings[:2] },
            "runtime_overhead": { "delta_boot_ms": 28.0, "delta_ram_mb": -4.2, "p99_frametime_ms": 16.6 },
            "early_hook_success": True,
            "runtime_api_resolved": True,
            "heap_scan_completed": True,
            "anti_hook_detected": False,
            "dump_blocked": False
        },
        "C3": { # IL2CPP Custom Metadata Encryption: Static dump fails (0%), Frida hook recovers decrypted heap!
            "static": { "classes": [], "methods": [], "strings": [] },
            "dynamic": { "classes": all_classes[:2], "methods": all_methods[:2], "strings": [all_strings[0], all_strings[1]] },
            "runtime_overhead": { "delta_boot_ms": 115.0, "delta_ram_mb": 24.0, "p99_frametime_ms": 17.2 },
            "early_hook_success": True,
            "runtime_api_resolved": True,
            "heap_scan_completed": True,
            "anti_hook_detected": False,
            "dump_blocked": False
        },
        "C4": { # IL2CPP Header Patched + Obfuscation: Static fails (0%), Dynamic Frida hook recovers partial heap
            "static": { "classes": [], "methods": [], "strings": [] },
            "dynamic": { "classes": [all_classes[0]], "methods": [all_methods[0]], "strings": [all_strings[0]] },
            "runtime_overhead": { "delta_boot_ms": 185.0, "delta_ram_mb": 31.5, "p99_frametime_ms": 18.4 },
            "early_hook_success": True,
            "runtime_api_resolved": False,
            "heap_scan_completed": True,
            "anti_hook_detected": False,
            "dump_blocked": False
        },
        "C5": { # IL2CPP Hardened Guard: Anti-Hooking / Trampoline Verification + Zero-Trust Crypto
            "static": { "classes": [], "methods": [], "strings": [] },
            "dynamic": { "classes": [], "methods": [], "strings": [] },
            "runtime_overhead": { "delta_boot_ms": 195.0, "delta_ram_mb": 32.5, "p99_frametime_ms": 18.5 },
            "early_hook_success": False, # Trampoline hook detected on il2cpp_init
            "runtime_api_resolved": False,
            "heap_scan_completed": False, # Aborted/suppressed by NativeIntegrityGuard
            "anti_hook_detected": True,
            "dump_blocked": True
        }
    }

    profile = scenario_profiles.get(condition, scenario_profiles["C1"])
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "condition": condition,
        "is_mock": True,
        "static_extraction": profile["static"],
        "dynamic_extraction": profile["dynamic"],
        "runtime_overhead": profile["runtime_overhead"],
        "early_hook_success": profile["early_hook_success"],
        "runtime_api_resolved": profile["runtime_api_resolved"],
        "heap_scan_completed": profile["heap_scan_completed"],
        "anti_hook_detected": profile.get("anti_hook_detected", False),
        "dump_blocked": profile.get("dump_blocked", False),
        # Backwards compatibility flat accessors for dynamic dump
        "classes": profile["dynamic"]["classes"],
        "methods": profile["dynamic"]["methods"],
        "strings": profile["dynamic"]["strings"],
        "metadata_detected": condition not in ["C3", "C4", "C5"]
    }

    with open(output_dump_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[MOCK-DUMP] Dual static/dynamic dump generated for {condition} at {output_dump_path}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Frida Dynamic Early Hook Dump Harness")
    parser.add_argument("--target", required=True, help="Path to HoneyPot.exe executable")
    parser.add_argument("--condition", default="C1", choices=["C0", "C1", "C2", "C3", "C4", "C5"])
    parser.add_argument("--script", default="tools/harness.js", help="Frida hook script path")
    parser.add_argument("--output", default=None, help="Output JSON path")
    parser.add_argument("--mock", action="store_true", help="Force synthetic dump simulation")
    args = parser.parse_args()

    output_path = args.output or f"output/dumps/{args.condition}_dump.json"

    if args.mock or not FRIDA_AVAILABLE or not os.path.exists(args.target):
        mock_dynamic_dump(args.condition, output_path)
    else:
        run_frida_spawn_hook(args.target, args.script, output_path)

if __name__ == "__main__":
    main()
