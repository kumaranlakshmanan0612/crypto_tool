#!/usr/bin/env python3
"""
hsm_clang_checker.py
CycurHSM Static Analyzer — Windows + Anaconda Compatible Version
Uses Clang AST to detect:
  - Session leaks
  - Missing CloseSession / CloseSessionAsync
  - Jobs not polled with PollHandle
  - Async close not polled
  - Max session violations

Outputs:
  - HTML report
  - JSON report
"""

import os
import sys
import argparse
import json
import re
from collections import defaultdict
from clang import cindex
from jinja2 import Template


# ============================================================================
#                     UNIVERSAL LIBCLANG LOADER (WINDOWS SAFE)
# ============================================================================
def load_libclang():
    """
    Auto-detect libclang / clang.dll from:
        1. Active conda env (preferred)
        2. pip clang package
        3. Otherwise raise a helpful error
    """

    print("[INFO] Searching for libclang in conda environment...")

    conda_prefix = os.environ.get("CONDA_PREFIX", "")

    if conda_prefix:
        candidate_dirs = [
            os.path.join(conda_prefix, "Library", "bin"),
            os.path.join(conda_prefix, "bin"),
        ]

        for d in candidate_dirs:
            if os.path.isdir(d):
                dlls = [f for f in os.listdir(d)
                        if ("clang" in f.lower()) and f.lower().endswith(".dll")]
                if dlls:
                    dll_path = os.path.join(d, dlls[0])
                    try:
                        cindex.Config.set_library_file(dll_path)
                        print(f"[OK] Loaded clang DLL: {dll_path}")
                        return
                    except Exception as e:
                        print(f"[WARN] Could not load {dll_path}: {e}")

    # Fallback: pip-installed clang package
    pip_lib_dir = os.path.join(os.path.dirname(cindex.__file__), "libs")
    if os.path.isdir(pip_lib_dir):
        for f in os.listdir(pip_lib_dir):
            if ("clang" in f.lower()) and f.endswith(".dll"):
                dll_path = os.path.join(pip_lib_dir, f)
                try:
                    cindex.Config.set_library_file(dll_path)
                    print(f"[OK] Loaded clang DLL from pip package: {dll_path}")
                    return
                except Exception:
                    pass

    # If we reach here, failure
    raise RuntimeError("""
[FATAL] libclang.dll / clang.dll not found.

Fix:
    conda create -n hsmtool python=3.12
    conda activate hsmtool
    conda install -c conda-forge clangdev

Then run:
    python hsm_clang_checker.py <source-folder>
""")


# Load libclang immediately
load_libclang()


# ============================================================================
#                           CycurHSM API Definitions
# ============================================================================
SESSION_OPEN_NAMES = ["ecy_hsm_Csai_OpenSession"]
SESSION_CLOSE_NAMES = ["ecy_hsm_Csai_CloseSession"]
SESSION_CLOSE_ASYNC_NAMES = ["ecy_hsm_Csai_CloseSessionAsync"]
POLL_HANDLE_NAMES = ["ecy_hsm_Csai_PollHandle"]

# All job-triggering APIs
JOB_START_NAMES = [
    "ecy_hsm_Csai_HashStart", "ecy_hsm_Csai_HashFast",
    "ecy_hsm_Csai_Update", "ecy_hsm_Csai_Finish",
    "ecy_hsm_Csai_MacGenerateFast", "ecy_hsm_Csai_MacVerifyFast",
    "ecy_hsm_Csai_MacGenerate", "ecy_hsm_Csai_MacVerify",
    "ecy_hsm_Csai_BulkMacVerifyFast", "ecy_hsm_Csai_BulkMacGenerateFast",
    "ecy_hsm_Csai_WriteKeyToNv", "ecy_hsm_Csai_WriteData",
    "ecy_hsm_Csai_DeleteData", "ecy_hsm_Csai_LoadKey",
    "ecy_hsm_Csai_LoadKeyFast", "ecy_hsm_Csai_GenerateKey",
    "ecy_hsm_Csai_TbRefTblPartInit", "ecy_hsm_Csai_TbRefTblPartUpdate",
    "ecy_hsm_Csai_TbRefTblPartFinish",
    "ecy_hsm_Csai_Encrypt", "ecy_hsm_Csai_Decrypt",
    "ecy_hsm_Csai_EncryptFast", "ecy_hsm_Csai_DecryptFast",
    "ecy_hsm_Csai_GetRandom", "ecy_hsm_Csai_GetRandomFast",
    "SHE_LoadKey", "SHE_PrepareKeyUpdate",
    "SHE_VerifyMac", "SHE_GenerateMac"
]


# ============================================================================
#                               HTML TEMPLATE
# ============================================================================
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CycurHSM Static Analysis Report</title>
  <style>
    body { font-family: Arial; margin:20px; }
    table { width:100%; border-collapse: collapse; }
    th, td { border:1px solid #ccc; padding:6px; }
    th { background:#eef; }
  </style>
</head>
<body>
<h1>CycurHSM Static Analysis Report</h1>

<h2>Summary</h2>
<p><b>Files scanned:</b> {{ files_scanned }}</p>
<p><b>Total issues:</b> {{ total_issues }}</p>
<p><b>Max sessions allowed:</b> {{ max_sessions }}</p>

{% for f in files %}
<h2>{{ f.path }}</h2>

{% if f.issues %}
<table>
<tr><th>Level</th><th>Type</th><th>Message</th><th>Line</th></tr>

{% for issue in f.issues %}
<tr>
  <td>{{ issue.level }}</td>
  <td>{{ issue.type }}</td>
  <td>{{ issue.message }}</td>
  <td>{{ issue.line }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No issues.</p>
{% endif %}

{% endfor %}
</body>
</html>
"""


# ============================================================================
#                           RepoAnalyzer CLASS
# ============================================================================
class RepoAnalyzer:
    def __init__(self, src_root, max_sessions=5, clang_args=None):
        self.src_root = os.path.abspath(src_root)
        self.max_sessions = max_sessions
        self.clang_args = clang_args or ["-std=c11"]

        self.index = cindex.Index.create()

        # storage
        self.session_opens = defaultdict(list)
        self.session_closes = defaultdict(list)
        self.session_async_closes = defaultdict(list)
        self.job_starts = []
        self.polls = []

        self.per_file_issues = defaultdict(list)
        self.files_scanned = 0

    # ----------------------------------------------------------
    def analyze(self):
        c_files = []
        for r, _, fs in os.walk(self.src_root):
            for f in fs:
                if f.endswith((".c", ".h", ".cpp")):
                    c_files.append(os.path.join(r, f))

        self.files_scanned = len(c_files)

        for f in c_files:
            print(f"[SCAN] {f}")
            try:
                tu = self.index.parse(f, args=self.clang_args)
            except:
                tu = self.index.parse(f, args=[])
            self._walk(tu.cursor, f)

        self._post_checks()

    # ----------------------------------------------------------
    def _walk(self, node, filepath):
        for child in node.get_children():
            self._visit(child, filepath)
            self._walk(child, filepath)

    # ----------------------------------------------------------
    def _visit(self, node, filepath):
        if node.kind != cindex.CursorKind.CALL_EXPR:
            return

        raw = "".join(tok.spelling for tok in node.get_tokens())

        # --- open session ---
        for name in SESSION_OPEN_NAMES:
            if name in raw:
                var = self._lhs(node)
                self.session_opens[var].append((filepath, node.location.line))

        # --- close session ---
        for name in SESSION_CLOSE_NAMES:
            if name in raw:
                arg = self._arg(raw)
                self.session_closes[arg].append((filepath, node.location.line))

        # --- async close ---
        for name in SESSION_CLOSE_ASYNC_NAMES:
            if name in raw:
                arg = self._arg(raw)
                self.session_async_closes[arg].append((filepath, node.location.line))

        # --- poll ---
        for name in POLL_HANDLE_NAMES:
            if name in raw:
                arg = self._arg(raw)
                self.polls.append((filepath, node.location.line, arg))

        # --- job start ---
        for name in JOB_START_NAMES:
            if name in raw:
                sess = self._arg(raw)
                hjob = self._hjob(raw)
                self.job_starts.append((filepath, node.location.line, sess, hjob))

    # ----------------------------------------------------------
    @staticmethod
    def _arg(raw):
        try:
            inner = raw.split("(", 1)[1].split(")", 1)[0]
            first = inner.split(",", 1)[0]
            return first.replace("&", "").strip()
        except:
            return "<unknown>"

    @staticmethod
    def _hjob(raw):
        m = re.search(r"&\s*(hJob\w*)", raw)
        return m.group(1) if m else None

    @staticmethod
    def _lhs(node):
        try:
            parent = node.semantic_parent
            tokens = " ".join(tok.spelling for tok in parent.get_tokens())
            calltxt = "".join(tok.spelling for tok in node.get_tokens())
            prefix = tokens.split(calltxt)[0]
            if "=" in prefix:
                return prefix.split("=")[-2].split()[-1]
        except:
            pass
        return "<anon>"

    # ============================================================================
    #                               POST CHECKS
    # ============================================================================
    def _post_checks(self):

        # --- Session leaks -------------------------------------------------------
        for sess, opens in self.session_opens.items():
            closed = (len(self.session_closes.get(sess, [])) +
                      len(self.session_async_closes.get(sess, [])))

            if closed < len(opens):
                for f, ln in opens:
                    self.per_file_issues[f].append({
                        "level": "ERROR",
                        "type": "SESSION_LEAK",
                        "message": f"Session '{sess}' opened but not closed",
                        "line": ln
                    })

        # --- Job not polled ------------------------------------------------------
        started = {h for (_, _, _, h) in self.job_starts if h}
        polled = {arg for (_, _, arg) in self.polls}

        for (f, ln, sess, hjob) in self.job_starts:
            if hjob and hjob not in polled:
                self.per_file_issues[f].append({
                    "level": "ERROR",
                    "type": "JOB_NOT_POLLED",
                    "message": f"Job '{hjob}' was started but never polled",
                    "line": ln
                })

        # --- Async close not polled in same file --------------------------------
        for sess, closes in self.session_async_closes.items():
            for f, ln in closes:
                if not any(pf == f for pf, _, _ in self.polls):
                    self.per_file_issues[f].append({
                        "level": "ERROR",
                        "type": "ASYNC_CLOSE_NOT_POLLED",
                        "message": f"CloseSessionAsync({sess}) but no PollHandle() in same file",
                        "line": ln
                    })

        # --- Max sessions --------------------------------------------------------
        active = [
            s for s in self.session_opens
            if (len(self.session_closes.get(s, [])) +
                len(self.session_async_closes.get(s, []))) == 0
        ]

        if len(active) > self.max_sessions:
            root = self.src_root
            self.per_file_issues[root].append({
                "level": "ERROR",
                "type": "MAX_SESSION_LIMIT",
                "message": f"{len(active)} active sessions exceed max {self.max_sessions}",
                "line": 0
            })

    # ============================================================================
    #                            REPORT GENERATION
    # ============================================================================
    def dump_reports(self, html_out, json_out):
        files_list = []
        total_issues = 0

        for fp, issues in self.per_file_issues.items():
            files_list.append({"path": os.path.relpath(fp, self.src_root),
                               "issues": issues})
            total_issues += len(issues)

        html = Template(HTML_TEMPLATE).render(
            files=files_list,
            files_scanned=self.files_scanned,
            total_issues=total_issues,
            max_sessions=self.max_sessions
        )

        with open(html_out, "w") as f:
            f.write(html)

        with open(json_out, "w") as jf:
            json.dump({
                "files_scanned": self.files_scanned,
                "total_issues": total_issues,
                "files": files_list,
                "max_sessions": self.max_sessions
            }, jf, indent=2)

        print(f"[OK] HTML report saved: {html_out}")
        print(f"[OK] JSON report saved: {json_out}")


# ============================================================================
#                                 MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="CycurHSM Static Analyzer")
    parser.add_argument("src", help="Source folder or repo")
    parser.add_argument("--max-sessions", type=int, default=5,
                        help="Maximum allowed active HSM sessions")
    parser.add_argument("--output-html", default="hsm_report.html")
    parser.add_argument("--output-json", default="hsm_report.json")

    # ADDED (ONLY CHANGE)
    parser.add_argument(
        "--clang-args", nargs="*", default=[],
        help="Extra clang arguments (paths etc.)"
    )

    args = parser.parse_args()

    # ADD "-Ifake_headers" ALWAYS
    clang_args = ["-Ifake_headers"] + args.clang_args

    analyzer = RepoAnalyzer(args.src, args.max_sessions, clang_args)
    analyzer.analyze()
    analyzer.dump_reports(args.output_html, args.output_json)


if __name__ == "__main__":
    main()
