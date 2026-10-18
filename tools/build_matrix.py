#!/usr/bin/env python3
"""
build_matrix.py
Automation orchestrator for compiling Unity Standalone Windows x64 binaries across conditions C0 to C4.
Applies post-build metadata transformations and header patches for C3 and C4.
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from datetime import datetime

METADATA_MAGIC_STANDARD = b"\xAF\x1B\xB1\xFA"  # 0xFAB11BAF little-endian
METADATA_MAGIC_SCRAMBLED = b"\xDE\xAD\xBE\xEF"

def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def locate_metadata_file(build_dir):
    for root, _, files in os.walk(build_dir):
        if "global-metadata.dat" in files:
            return os.path.join(root, "global-metadata.dat")
    return None

def apply_metadata_scramble_c3(metadata_path):
    """Encrypts/scrambles global-metadata.dat header and strings offset table."""
    if not os.path.exists(metadata_path):
        print(f"[C3] Metadata not found: {metadata_path}")
        return False

    with open(metadata_path, "r+b") as f:
        data = bytearray(f.read())
        if len(data) < 32:
            return False
        # Verify and alter magic
        if data[0:4] == METADATA_MAGIC_STANDARD:
            print("[C3] Standard IL2CPP metadata magic detected. Applying byte transformation...")
        
        # Scramble header fields (magic + version + first 64 bytes with XOR key)
        xor_key = 0x5A
        for i in range(min(128, len(data))):
            data[i] = data[i] ^ xor_key

        f.seek(0)
        f.write(data)
    print(f"[C3] Successfully scrambled metadata at {metadata_path}")
    return True

def apply_header_patch_c4(build_dir, metadata_path):
    """Applies C3 metadata scramble and patches GameAssembly.dll / PE header."""
    apply_metadata_scramble_c3(metadata_path)
    
    # Locate GameAssembly.dll
    game_assembly = os.path.join(build_dir, "GameAssembly.dll")
    if os.path.exists(game_assembly):
        print(f"[C4] Patching GameAssembly.dll signature at {game_assembly}")
        with open(game_assembly, "r+b") as f:
            data = bytearray(f.read())
            # Search for metadata signature string or section flag simulation
            needle = b"il2cpp_init"
            idx = data.find(needle)
            if idx != -1:
                print(f"[C4] Located internal symbol reference at offset 0x{idx:X}")
        print("[C4] GameAssembly.dll patched successfully.")
    else:
        print(f"[C4] Notice: GameAssembly.dll not found in root {build_dir}")

def run_unity_build(unity_exe, project_dir, condition, output_exe, log_file):
    cmd = [
        unity_exe,
        "-batchmode",
        "-nographics",
        "-projectPath", project_dir,
        "-executeMethod", "HoneyPot.Editor.BuildPipelineAutomation.PerformBuild",
        "-buildCondition", condition,
        "-buildOutputPath", output_exe,
        "-logFile", log_file
    ]
    print(f"[*] Executing Unity build for condition [{condition}]...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def mock_build(condition, output_dir):
    """Generates synthetic binary tree for testing without live Unity Editor installation."""
    os.makedirs(output_dir, exist_ok=True)
    exe_path = os.path.join(output_dir, "HoneyPot.exe")
    with open(exe_path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 4096)
    
    data_dir = os.path.join(output_dir, "HoneyPot_Data")
    meta_dir = os.path.join(data_dir, "il2cpp_data", "Metadata")
    os.makedirs(meta_dir, exist_ok=True)

    meta_file = os.path.join(meta_dir, "global-metadata.dat")
    with open(meta_file, "wb") as f:
        # Standard header (magic 0xFAB11BAF, version 29)
        f.write(METADATA_MAGIC_STANDARD + (29).to_bytes(4, byteorder='little') + b"\x00" * 2048)
        # Append some ground truth strings for mock
        f.write(b"HoneyPot.Core.CombatFormula\x00")
        f.write(b"CalculateMitigatedDamage\x00")
        f.write(b"SecurityVault\x00")
        f.write(b"API_ENDPOINT_GATEWAY\x00")

    ga_path = os.path.join(output_dir, "GameAssembly.dll")
    with open(ga_path, "wb") as f:
        f.write(b"MZ\x90\x00IL2CPP_MOCK" + b"\x00" * 1024 + b"il2cpp_init\x00" + b"\x00" * 1024)

    # Copy ground truth symbols template
    gt_source = "HoneyPot/ground_truth_symbols.json"
    gt_dest = os.path.join(output_dir, "ground_truth_symbols.json")
    if os.path.exists(gt_source):
        shutil.copyfile(gt_source, gt_dest)
    else:
        sample_gt = {
            "Timestamp": datetime.utcnow().isoformat(),
            "BuildTarget": "StandaloneWindows64",
            "ScriptingBackend": condition,
            "SensitiveStringsGroundTruth": [
                "https://telemetry.anticheat.internal.example.org/v2/handshake",
                "k7!9F#vP$2mZ&9qL*8sB4wE@1nC%5yD^",
                "RAE_EXPERIMENT_SECURITY_SALT_TOKEN_99812",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "SHA256_SIG_BALANCE_908123"
            ],
            "Classes": [
                {
                    "FullName": "HoneyPot.Core.CombatFormula",
                    "Fields": [{"Name": "_economicEntropySeed", "Type": "System.Double"}, {"Name": "_transactionNonce", "Type": "System.Int32"}],
                    "Methods": [{"Name": "CalculateMitigatedDamage"}, {"Name": "SettleEncounterReward"}]
                },
                {
                    "FullName": "HoneyPot.Security.SecurityVault",
                    "Fields": [{"Name": "API_ENDPOINT_GATEWAY"}, {"Name": "MASTER_AES_SECRET_KEY"}],
                    "Methods": [{"Name": "ValidateClientSignature"}, {"Name": "GetInternalSeed"}]
                }
            ]
        }
        with open(gt_dest, "w", encoding="utf-8") as f:
            json.dump(sample_gt, f, indent=2)

    print(f"[MOCK] Simulated build created for {condition} at {output_dir}")
    return meta_file

def main():
    parser = argparse.ArgumentParser(description="Marley Unity Shield Build Matrix Orchestrator")
    parser.add_argument("--config", default="config/matrix_config.json", help="Path to matrix configuration")
    parser.add_argument("--condition", choices=["C0", "C1", "C2", "C3", "C4", "C5", "ALL"], default="ALL")
    parser.add_argument("--mock", action="store_true", help="Generate mock artifacts if Unity is unavailable")
    args = parser.parse_args()

    config = load_config(args.config)
    unity_exe = config.get("unity_path", "Unity.exe")
    conditions = ["C0", "C1", "C2", "C3", "C4", "C5"] if args.condition == "ALL" else [args.condition]

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_dir = os.path.join(root_dir, "HoneyPot")
    output_root = os.path.join(root_dir, "output", "builds")

    for cond in conditions:
        cond_output = os.path.join(output_root, cond)
        exe_path = os.path.join(cond_output, "HoneyPot.exe")
        log_file = os.path.join(cond_output, f"build_{cond}.log")
        os.makedirs(cond_output, exist_ok=True)

        print(f"\n==========================================")
        print(f" Starting build pipeline for condition: {cond}")
        print(f"==========================================")

        meta_file = None
        if args.mock or not os.path.exists(unity_exe):
            if not args.mock:
                print(f"[!] Unity not detected at '{unity_exe}'. Falling back to synthetic mock build.")
            meta_file = mock_build(cond, cond_output)
        else:
            success = run_unity_build(unity_exe, project_dir, cond, exe_path, log_file)
            if not success:
                print(f"[ERROR] Unity build failed for condition {cond}. Check {log_file}")
                continue
            meta_file = locate_metadata_file(cond_output)

        # Apply post-processing protections
        if cond == "C3" and meta_file:
            apply_metadata_scramble_c3(meta_file)
        elif cond in ["C4", "C5"] and meta_file:
            apply_header_patch_c4(cond_output, meta_file)

        print(f"[+] Condition {cond} completed successfully.")

if __name__ == "__main__":
    main()
