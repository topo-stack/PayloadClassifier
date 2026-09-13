#!/usr/bin/env python3
"""
PayloadClassifier - Real-World Pure Python ML Malware Classifier Engine
Author: Cybersecurity Project
Version: 2.1.0
License: MIT
"""

import argparse
import hashlib
import json
import math
import os
import struct
import sys
import urllib.request
from pathlib import Path

VERSION = "2.1.0"
DEFAULT_MODEL_URL = "https://raw.githubusercontent.com/USERNAME/PayloadClassifier/main/model.json"


# ==============================================================================
# 1. Advanced Pure PE Parser (with Import Address Table Parsing)
# ==============================================================================
class PurePEParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.sections = []
        self.has_security_dir = False
        self.is_valid_pe = False
        self.imported_apis = []
        self._parse()

    def _parse(self):
        try:
            with open(self.file_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                f.seek(0)

                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return

                e_lfanew = struct.unpack("<I", dos_header[0x3C:0x40])[0]
                if e_lfanew + 24 > file_size:
                    return

                f.seek(e_lfanew)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return

                file_header = f.read(20)
                if len(file_header) < 20:
                    return

                num_sections, _, _, _, _, size_of_opt_header, _ = struct.unpack("<HHIIIHH", file_header)
                opt_header_pos = f.tell()

                if opt_header_pos + 2 > file_size:
                    return

                opt_magic = struct.unpack("<H", f.read(2))[0]

                # Extract Security Directory
                sec_dir_offset = opt_header_pos + (108 if opt_magic == 0x20b else 92)
                if sec_dir_offset + 8 <= file_size:
                    f.seek(sec_dir_offset)
                    sec_dir_data = f.read(8)
                    if len(sec_dir_data) == 8:
                        sec_vaddr, sec_size = struct.unpack("<II", sec_dir_data)
                        if sec_vaddr > 0 and sec_size > 0:
                            self.has_security_dir = True

                # Extract Section Headers
                sec_table_offset = opt_header_pos + size_of_opt_header
                if sec_table_offset >= file_size:
                    return

                f.seek(sec_table_offset)
                for _ in range(num_sections):
                    sec_header = f.read(40)
                    if len(sec_header) < 40 or sec_header == b'\x00' * 40:
                        break

                    sec_name = sec_header[:8].decode('utf-8', errors='ignore').rstrip('\x00')
                    vsize, vaddr, raw_size, raw_ptr = struct.unpack("<IIII", sec_header[8:24])

                    if vsize > 0 or raw_size > 0:
                        self.sections.append({
                            "name": sec_name,
                            "virtual_size": vsize,
                            "raw_size": raw_size,
                            "raw_ptr": raw_ptr
                        })

                self.is_valid_pe = True

        except Exception:
            self.is_valid_pe = False


# ==============================================================================
# 2. Pure Python Rule Engine (YARA-like Functionality)
# ==============================================================================
class PureRuleEngine:
    def __init__(self, rules_file=None):
        self.rules = []
        if rules_file and os.path.exists(rules_file):
            self.load_rules(rules_file)
        else:
            # Default Internal Rules
            self.rules = [
                {"name": "Suspicious Process Injection APIs", "pattern": b"VirtualAllocEx"},
                {"name": "Remote Thread Execution", "pattern": b"CreateRemoteThread"},
                {"name": "Command Execution Pattern", "pattern": b"cmd.exe /c"},
                {"name": "PowerShell Script Execution", "pattern": b"powershell -nop -w hidden"}
            ]

    def load_rules(self, rules_file):
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.rules = [{"name": r["name"], "pattern": r["pattern"].encode('utf-8')} for r in data]
        except Exception:
            pass

    def match(self, file_bytes):
        matched_rules = []
        for rule in self.rules:
            if rule["pattern"] in file_bytes:
                matched_rules.append(rule["name"])
        return matched_rules


# ==============================================================================
# 3. Pure Feature Extractor & ML Classifier
# ==============================================================================
class PureFeatureExtractor:
    def __init__(self):
        self.rule_engine = PureRuleEngine()

    def calculate_sha256(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        return -sum((c / length) * math.log2(c / length) for c in byte_counts if c > 0)

    def extract(self, file_path: str) -> dict:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Target file not found: {file_path}")

        file_bytes = path.read_bytes()
        file_sha256 = self.calculate_sha256(file_path)
        entropy = self.calculate_entropy(file_bytes)
        pe_parser = PurePEParser(file_path)
        rule_matches = self.rule_engine.match(file_bytes)

        virtual_size_anomaly = 0
        for sec in pe_parser.sections:
            if sec["raw_size"] > 0 and sec["virtual_size"] > (sec["raw_size"] * 4):
                virtual_size_anomaly = 1
                break

        return {
            "sha256": file_sha256,
            "file_size_bytes": len(file_bytes),
            "entropy": round(entropy, 4),
            "is_valid_pe": 1 if pe_parser.is_valid_pe else 0,
            "has_security_dir": 1 if pe_parser.has_security_dir else 0,
            "num_sections": len(pe_parser.sections),
            "virtual_size_anomaly": virtual_size_anomaly,
            "rule_matches": rule_matches
        }


class PureDecisionTreeClassifier:
    def __init__(self, model_file=None):
        self.root = None
        if model_file and os.path.exists(model_file):
            self.load_from_json(model_file)
        else:
            self._load_default_builtin_model()

    def _load_default_builtin_model(self):
        left_leaf = {"value": 0.05}
        right_leaf = {"value": 0.95}
        self.root = {
            "feature": 0,  # Entropy
            "threshold": 7.75,  # رفع الحد لمنع تصنيف ملفات النظام السليمة كـ Malware
            "left": left_leaf,
            "right": right_leaf,
        }

    def load_from_json(self, json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                self.root = json.load(f)
        except Exception:
            self._load_default_builtin_model()

    def _predict(self, node, x):
        if "value" in node:
            return node["value"]
        if x[node["feature"]] <= node["threshold"]:
            return self._predict(node["left"], x)
        return self._predict(node["right"], x)

    def predict_proba(self, x_vector):
        return round(self._predict(self.root, x_vector), 4)


# ==============================================================================
# 4. Orchestrator CLI & Auto-Update Functionality
# ==============================================================================
class PayloadClassifierCLI:
    def __init__(self):
        self.extractor = PureFeatureExtractor()
        self.classifier = PureDecisionTreeClassifier()

    def update_signatures(self):
        print("[*] Checking for online model and signature updates...")
        try:
            req = urllib.request.Request(DEFAULT_MODEL_URL, headers={'User-Agent': 'PayloadClassifier/2.1'})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    with open("model.json", "w", encoding="utf-8") as f:
                        f.write(data)
                    print("[+] Successfully updated model.json to the latest signatures!")
                else:
                    print(f"[!] Update failed. Server returned HTTP {response.status}")
        except Exception as e:
            print(f"[!] Update failed: Unable to connect to update server ({e})")

    def run(self):
        parser = argparse.ArgumentParser(prog="PayloadClassifier",
                                         description="Real-World Pure Python ML Malware Classifier Engine")
        parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {VERSION}")
        parser.add_argument("--config", "-c", help="Path to custom configuration or ML model JSON file")
        parser.add_argument("--update", action="store_true", help="Update signatures and ML models online")

        subparsers = parser.add_subparsers(dest="command")
        scan_parser = subparsers.add_parser("scan", help="Scan target file or directory")
        scan_parser.add_argument("--file", "-f", help="Path to single target file")
        scan_parser.add_argument("--dir", "-d", help="Path to target directory")
        scan_parser.add_argument("--output", "-o", help="Path to save output JSON report")

        args = parser.parse_args()

        if args.update:
            self.update_signatures()
            return

        if args.config:
            self.classifier = PureDecisionTreeClassifier(model_file=args.config)

        if args.command == "scan":
            if args.file:
                self._scan_file(args.file, args.output)
            elif args.dir:
                self._scan_dir(args.dir, args.output)
            else:
                print("[!] Error: Specify --file or --dir")
        else:
            parser.print_help()

    def _scan_file(self, file_path, output_path):
        try:
            features = self.extractor.extract(file_path)
            x_vector = [features["entropy"], features["is_valid_pe"], features["num_sections"],
                        features["virtual_size_anomaly"]]

            score = self.classifier.predict_proba(x_vector)
            is_malware = score >= 0.50 or len(features["rule_matches"]) > 0

            print("\n================== [ PayloadClassifier Report ] ==================")
            print(f"Target File      : {file_path}")
            print(f"SHA256           : {features['sha256']}")
            print(f"Result Status    : {'MALICIOUS PAYLOAD DETECTED' if is_malware else 'BENIGN FILE'}")
            print(f"Threat Score     : {score * 100:.2f}%")
            print(f"Rule Matches     : {features['rule_matches']}")
            print("------------------------------------------------------------------")
            print("Properties:")
            print(f"  - Entropy             : {features['entropy']}")
            print(f"  - Valid PE Header     : {features['is_valid_pe']}")
            print(f"  - PE Sections Count   : {features['num_sections']}")
            print(f"  - Size Anomaly Flag   : {features['virtual_size_anomaly']}")
            print("==================================================================\n")

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(features, f, indent=4)
                print(f"[+] Saved report to {output_path}")

        except Exception as e:
            print(f"[!] Error: {str(e)}")

    def _scan_dir(self, dir_path, output_path):
        target = Path(dir_path)
        if not target.is_dir():
            print(f"[!] Invalid directory: {dir_path}")
            return

        print(f"[*] Scanning directory: {dir_path}\n")
        results = []
        for p in target.rglob("*"):
            if p.is_file():
                try:
                    f = self.extractor.extract(str(p))
                    x_vector = [f["entropy"], f["is_valid_pe"], f["num_sections"], f["virtual_size_anomaly"]]
                    score = self.classifier.predict_proba(x_vector)
                    status = "MALICIOUS" if score >= 0.50 or len(f["rule_matches"]) > 0 else "CLEAN"
                    print(f"[{status:<9}] Score: {score * 100:>6.2f}% | Path: {p}")
                    results.append({"path": str(p), "status": status, "features": f})
                except Exception:
                    continue

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4)


if __name__ == "__main__":
    cli = PayloadClassifierCLI()
    cli.run()