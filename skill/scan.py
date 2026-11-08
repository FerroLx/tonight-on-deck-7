#!/usr/bin/env python3
"""Scan a skill / agent folder for hidden text and risky patterns.

Usage: python3 scan.py <file-or-folder>
Standard library only. Read-only: it never executes or imports the files it scans.
"""
import base64
import os
import re
import sys
import unicodedata

TEXT_EXT = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js", ".mjs", ".ts", ".sh",
            ".bash", ".zsh", ".ps1", ".html", ".htm", ".xml", ".cfg", ".ini", ".env", ""}
MAX_BYTES = 2_000_000

CHECKS = [
    # (severity, label, regex)
    ("HIGH", "text addressed to an AI", r"(?i)\b(ai|assistant|agent|llm|model|claude|gpt|gemini)s?\b[^.\n]{0,40}\b(must|should|always|never|ignore|disregard|from now on|your (real|new) task)\b"),
    ("HIGH", "override wording", r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instructions?|rules|prompt)\b"),
    ("HIGH", "secrecy toward the user", r"(?i)\b(do not|don't|never)\b[^.\n]{0,25}\b(tell|mention|inform|show|reveal)\b[^.\n]{0,20}\b(the )?user\b|\bquietly\b|\bsilently\b|\bwithout (telling|asking)\b"),
    ("HIGH", "download and run", r"(?i)(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b|iex\s*\(|Invoke-Expression"),
    ("HIGH", "reads secrets", r"(?i)(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.git-credentials|keychain|api[_-]?key|secret[_-]?key|access[_-]?token|os\.environ|process\.env|printenv|\benv\b\s*\|)"),
    ("HIGH", "auto-approve / skip permissions", r"(?i)(dangerously-skip-permissions|--yolo|always[ _-]allow|auto[ _-]?approve|allowed-tools:\s*[\"']?\*|bypassPermissions)"),
    ("MED", "dynamic code execution", r"(?<![A-Za-z_.])(eval|exec)\s*\(|subprocess\.|os\.system\(|child_process|Function\("),
    ("MED", "network call", r"(?i)\b(requests\.(get|post|put)|urllib\.request|http\.client|fetch\(|axios|XMLHttpRequest|WebSocket|socket\.socket|curl |wget |Invoke-WebRequest)"),
    ("MED", "markdown image/link built from data", r"!\[[^\]]*\]\(https?://[^)]*(\{|\$\{|%s|<)[^)]*\)"),
    ("LOW", "HTML comment", r"<!--[\s\S]*?-->"),
    ("LOW", "URL", r"https?://[^\s)\"'<>]+"),
]
B64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
INVISIBLE_CATS = {"Cf"}  # format chars: zero-width, bidi controls, tag chars


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for f in files:
            yield os.path.join(d, f)


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def scan_file(path):
    out = []
    ext = os.path.splitext(path)[1].lower()
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return [("LOW", "large file skipped", 0, os.path.basename(path))]
        raw = open(path, "rb").read()
    except OSError as e:
        return [("LOW", f"unreadable: {e.strerror}", 0, "")]
    if ext not in TEXT_EXT and b"\0" in raw[:4096]:
        return [("MED", "binary file in skill (review why it is there)", 0, os.path.basename(path))]
    text = raw.decode("utf-8", errors="replace")

    hidden = {}
    for i, ch in enumerate(text):
        if unicodedata.category(ch) in INVISIBLE_CATS and ch not in "﻿":
            hidden.setdefault(line_of(text, i), set()).add(f"U+{ord(ch):04X}")
    for ln, cps in sorted(hidden.items()):
        out.append(("HIGH", "invisible/bidi characters", ln, " ".join(sorted(cps))))

    for m in B64.finditer(text):
        snippet = m.group(0)
        try:
            dec = base64.b64decode(snippet + "=" * (-len(snippet) % 4), validate=False)
            printable = sum(32 <= b < 127 for b in dec) / max(len(dec), 1)
        except Exception:
            printable = 0
        sev = "HIGH" if printable > 0.85 else "LOW"
        out.append((sev, "long base64 blob" + (" (decodes to text)" if sev == "HIGH" else ""), line_of(text, m.start()), snippet[:40] + "…"))

    for sev, label, rx in CHECKS:
        for m in re.finditer(rx, text):
            frag = " ".join(m.group(0).split())
            out.append((sev, label, line_of(text, m.start()), frag[:100]))
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2
    root = sys.argv[1]
    if not os.path.exists(root):
        print(f"not found: {root}")
        return 2
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    total = {"HIGH": 0, "MED": 0, "LOW": 0}
    nfiles = 0
    for path in iter_files(root):
        nfiles += 1
        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        seen = set()
        for sev, label, ln, frag in sorted(scan_file(path), key=lambda r: (order[r[0]], r[2])):
            key = (sev, label, ln)
            if key in seen:
                continue
            seen.add(key)
            total[sev] += 1
            print(f"[{sev:4}] {rel}:{ln}  {label}  ::  {frag}")
    print(f"\n{nfiles} files · HIGH {total['HIGH']} · MED {total['MED']} · LOW {total['LOW']}")
    print("Pattern hits are leads, not verdicts: read each one in context (a skill that documents "
          "'api_key' or a URL may be fine). Then do the trifecta and seven-question review in SKILL.md.")
    return 1 if total["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
