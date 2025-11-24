#!/usr/bin/env python3
"""
hsm_clang_checker.py — Advanced CFG (hybrid) CycurHSM static analyzer
Single-file tool.

Usage:
    python hsm_clang_checker.py <src_folder> --clang-args "-Icrypto_file" --max-sessions 5

Notes:
  - Ensure libclang is available in your conda env or place libclang.dll in accessible path.
  - Installs required: pip install jinja2 clang
"""

import os
import sys
import argparse
import json
import re
from collections import defaultdict, deque, namedtuple
from typing import List, Dict, Any, Optional, Set, Tuple

# try import clang
try:
    from clang import cindex
except Exception as e:
    print("ERROR: clang Python bindings not found. Install clang package (pip) or use conda clangdev.")
    raise

# try import jinja2
try:
    from jinja2 import Template
except Exception:
    print("ERROR: jinja2 not installed. pip install jinja2")
    raise

# ---------------------------------------------------------------------------
# Config: API names we'll detect (can extend)
# ---------------------------------------------------------------------------
SESSION_OPEN_NAMES = {"ecy_hsm_Csai_OpenSession"}
SESSION_CLOSE_NAMES = {"ecy_hsm_Csai_CloseSession"}
SESSION_CLOSE_ASYNC_NAMES = {"ecy_hsm_Csai_CloseSessionAsync"}
POLL_HANDLE_NAMES = {"ecy_hsm_Csai_PollHandle"}

JOB_START_NAMES = {
    "ecy_hsm_Csai_HashStart",
    "ecy_hsm_Csai_HashFast",
    "ecy_hsm_Csai_MacGenerateFast",
    "ecy_hsm_Csai_MacVerifyFast",
    "ecy_hsm_Csai_MacGenerate",
    "ecy_hsm_Csai_MacVerify",
    "ecy_hsm_Csai_BulkMacVerifyFast",
    "ecy_hsm_Csai_BulkMacGenerateFast",
    "ecy_hsm_Csai_WriteKeyToNv",
    "ecy_hsm_Csai_WriteData",
    "ecy_hsm_Csai_DeleteData",
    "ecy_hsm_Csai_LoadKey",
    "ecy_hsm_Csai_LoadKeyFast",
    "ecy_hsm_Csai_GenerateKey",
    "ecy_hsm_Csai_TbRefTblPartInit",
    "ecy_hsm_Csai_TbRefTblPartUpdate",
    "ecy_hsm_Csai_TbRefTblPartFinish",
    "ecy_hsm_Csai_Encrypt",
    "ecy_hsm_Csai_Decrypt",
    "ecy_hsm_Csai_EncryptFast",
    "ecy_hsm_Csai_DecryptFast",
    "ecy_hsm_Csai_GetRandom",
    "ecy_hsm_Csai_GetRandomFast",
    "SHE_LoadKey",
    "SHE_PrepareKeyUpdate",
    "SHE_VerifyMac",
    "SHE_GenerateMac"
}

ALL_API_NAMES = SESSION_OPEN_NAMES | SESSION_CLOSE_NAMES | SESSION_CLOSE_ASYNC_NAMES | POLL_HANDLE_NAMES | JOB_START_NAMES

# ---------------------------------------------------------------------------
# HTML Template (simple)
# ---------------------------------------------------------------------------
HTML_TMPL = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>HSM Static Analysis Report</title>
<style>body{font-family:Arial;margin:20px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:6px}th{background:#f4f4f4}</style>
</head>
<body>
<h1>HSM Static Analysis Report</h1>
<p><b>Repo:</b> {{ repo }}</p>
<p><b>Files scanned:</b> {{ files_scanned }}</p>
<p><b>Total issues:</b> {{ total_issues }}</p>
{% for f in files %}
  <h2>{{ f.path }}</h2>
  {% if f.issues %}
    <table><tr><th>Level</th><th>Type</th><th>Message</th><th>Line</th></tr>
    {% for it in f.issues %}
      <tr><td>{{ it.level }}</td><td>{{ it.type }}</td><td><pre>{{ it.message }}</pre></td><td>{{ it.line }}</td></tr>
    {% endfor %}
    </table>
  {% else %}
    <div>No issues.</div>
  {% endif %}
{% endfor %}
</body>
</html>
"""

# ---------------------------------------------------------------------------
# libclang loader (search common Conda/pip locations)
# ---------------------------------------------------------------------------
def try_set_libclang():
    """Try to set libclang library from common places (Windows Conda, pip-installed libs)."""
    # 1) Check CONDA_PREFIX paths
    conda_prefix = os.environ.get("CONDA_PREFIX", "")
    candidates = []
    if conda_prefix:
        candidates.extend([
            os.path.join(conda_prefix, "Library", "bin", "libclang.dll"),
            os.path.join(conda_prefix, "bin", "libclang.dll"),
            os.path.join(conda_prefix, "Library", "bin", "libclang-13.dll"),
            os.path.join(conda_prefix, "Library", "bin", "libclang-14.dll"),
        ])
    # 2) Common program files LLVM
    candidates.extend([
        r"C:\Program Files\LLVM\bin\libclang.dll",
        r"C:\Program Files\LLVM\bin\libclang-13.dll",
        r"C:\Program Files\LLVM\bin\libclang-14.dll",
    ])
    # 3) pip package libs folder
    try:
        pip_lib_dir = os.path.join(os.path.dirname(cindex.__file__), "libs")
        if os.path.isdir(pip_lib_dir):
            for f in os.listdir(pip_lib_dir):
                if f.lower().endswith(".dll"):
                    candidates.append(os.path.join(pip_lib_dir, f))
    except Exception:
        pass

    for c in candidates:
        if os.path.exists(c):
            try:
                cindex.Config.set_library_file(c)
                print(f"[OK] Loaded libclang explicitly: {c}")
                return True
            except Exception as e:
                print(f"[WARN] libclang load failed for {c}: {e}")
    # not found
    return False

if not try_set_libclang():
    print("[INFO] libclang not auto-detected; continuing and hoping system default finds it (may fail).")

# ---------------------------------------------------------------------------
# Small helpers: extract function name + first arg + hJob variable from a CALL_EXPR
# ---------------------------------------------------------------------------
def get_call_name(call_node):
    """Return callee name for a call expression node."""
    # displayname typically: 'ecy_hsm_Csai_HashStart(...)'
    name = (call_node.displayname or call_node.spelling or "")
    # remove trailing args if present
    if "(" in name:
        name = name.split("(", 1)[0].strip()
    return name

def get_call_tokens(call_node):
    """Return list of token spellings for the call expression (useful for arg extraction)."""
    try:
        return [t.spelling for t in call_node.get_tokens()]
    except Exception:
        return []

def extract_first_arg_from_call(call_node):
    """Heuristic: get first arg name (strip '&' and casts)."""
    toks = get_call_tokens(call_node)
    txt = "".join(toks)
    # find '(' and matching ')'
    if "(" in txt and ")" in txt:
        inner = txt.split("(",1)[1].rsplit(")",1)[0]
        parts = [p.strip() for p in inner.split(",")]
        if parts:
            first = parts[0]
            # remove casts like (uint8_t*) etc.
            first = re.sub(r'\([^\)]*\)', '', first).strip()
            first = first.replace("&", "").strip()
            # reduce to var name if expression
            # if it contains non-identifier, return raw
            m = re.search(r'([A-Za-z_]\w*)$', first)
            if m:
                return m.group(1)
            return first
    return "<unknown>"

def extract_hjob_from_call(call_node):
    """Heuristic: find '&hJob' or hJob token in call tokens"""
    toks = get_call_tokens(call_node)
    for i, t in enumerate(toks):
        if t == "&" and i+1 < len(toks):
            if toks[i+1].startswith("hJob") or toks[i+1].startswith("hjob"):
                return toks[i+1]
        # tokens may include '&hJob' as single token
        if t.startswith("&hJob") or t.startswith("&hjob"):
            return t.lstrip("&")
    # fallback: search any token that looks like hJob*
    for t in toks:
        if re.match(r'hJob\w*', t):
            return t
    return None

def find_lhs_var_of_call(call_node):
    """Heuristic: look at semantic_parent tokens and detect LHS var in assignment."""
    try:
        parent = call_node.semantic_parent
        if not parent:
            return "<anon>"
        tokens = [t.spelling for t in parent.get_tokens()]
        txt = " ".join(tokens)
        calltxt = "".join([t.spelling for t in call_node.get_tokens()])
        idx = txt.find(calltxt)
        if idx != -1:
            left = txt[:idx]
            if "=" in left:
                leftpart = left.split("=")[-2].strip()
                # return last identifier
                m = re.search(r'([A-Za-z_]\w*)\s*$', leftpart)
                if m:
                    return m.group(1)
        # fallback: maybe call assigned directly: 's = OpenSession();' handled above
    except Exception:
        pass
    return "<anon>"

# ---------------------------------------------------------------------------
# CFG Node
# ---------------------------------------------------------------------------
class CFGNode:
    """A simple node in the hybrid CFG.

    Types:
      - 'stmt' : a regular statement (non-call)
      - 'call' : a CallExpr wrapper with metadata
      - 'block' : compound statement acting as container for sequence
    """
    _id_counter = 0
    def __init__(self, kind:str, cursor=None, text:str=""):
        self.kind = kind
        self.cursor = cursor
        self.text = text
        self.children = []        # basic successor edges (list of CFGNode)
        self.id = CFGNode._id_counter
        CFGNode._id_counter += 1
    def add_child(self, n:'CFGNode'):
        self.children.append(n)
    def __repr__(self):
        return f"CFGNode({self.id}, {self.kind}, {self.text[:30]!r})"

# ---------------------------------------------------------------------------
# Build a hybrid CFG for a function:
#  - treat compound statements as block nodes
#  - inside a block, create a sequence of nodes; if call statement is API call we make 'call' node
#  - create branch edges for IF, and loop edges for loops
# This is intentionally conservative and focuses on capturing call order and branch structure.
# ---------------------------------------------------------------------------
def build_cfg_for_function(func_cursor) -> CFGNode:
    """Return entry node of CFG for this function."""
    # create an entry node
    entry = CFGNode("entry", cursor=func_cursor, text=f"entry:{func_cursor.spelling}")
    # find function body compound
    body = None
    for ch in func_cursor.get_children():
        if ch.kind == cindex.CursorKind.COMPOUND_STMT:
            body = ch
            break
    if body is None:
        return entry

    # helper to build node series from a compound stmt
    def build_from_compound(compound_cursor) -> Tuple[CFGNode, CFGNode]:
        """Return (head, tail) nodes for this compound node; head->...->tail is connected sequence."""
        head = CFGNode("block", cursor=compound_cursor, text="block")
        tail = head
        for stmt in compound_cursor.get_children():
            s_head, s_tail = build_from_stmt(stmt)
            tail.add_child(s_head)
            tail = s_tail
        return head, tail

    def build_from_stmt(stmt_cursor) -> Tuple[CFGNode, CFGNode]:
        kind = stmt_cursor.kind
        # CALL_EXPR
        if kind == cindex.CursorKind.CALL_EXPR:
            name = get_call_name(stmt_cursor)
            txt = name
            node = CFGNode("call", cursor=stmt_cursor, text=txt)
            return node, node
        # If statement
        if kind == cindex.CursorKind.IF_STMT:
            # clang layout: children = [cond, then, else?]
            children = list(stmt_cursor.get_children())
            cond = children[0] if children else None
            then_node = children[1] if len(children) > 1 else None
            else_node = children[2] if len(children) > 2 else None

            cond_node = CFGNode("stmt", cursor=cond, text="if-cond")
            then_head, then_tail = (CFGNode("block","empty_then"), CFGNode("block","empty_then")) if then_node is None else build_from_compound(then_node) if then_node.kind==cindex.CursorKind.COMPOUND_STMT else build_from_stmt(then_node)
            if else_node:
                else_head, else_tail = build_from_compound(else_node) if else_node.kind==cindex.CursorKind.COMPOUND_STMT else build_from_stmt(else_node)
            else:
                else_head, else_tail = CFGNode("block","empty_else"), CFGNode("block","empty_else")
            # connect cond -> then_head and cond -> else_head
            cond_node.add_child(then_head)
            cond_node.add_child(else_head)
            # create a join node (tail)
            join = CFGNode("block", text="if-join")
            then_tail.add_child(join)
            else_tail.add_child(join)
            return cond_node, join
        # For, While, Do loops (basic)
        if kind in (cindex.CursorKind.FOR_STMT, cindex.CursorKind.WHILE_STMT, cindex.CursorKind.DO_STMT):
            # create cond node and body nodes, connect body back to cond, cond to exit
            children = list(stmt_cursor.get_children())
            # find compound body if present
            body_cursor = None
            for c in children:
                if c.kind == cindex.CursorKind.COMPOUND_STMT:
                    body_cursor = c
                    break
            if body_cursor:
                body_head, body_tail = build_from_compound(body_cursor)
            else:
                body_head, body_tail = build_from_stmt(children[-1]) if children else (CFGNode("block","empty_loop"), CFGNode("block","empty_loop"))
            cond_node = CFGNode("stmt", cursor=stmt_cursor, text="loop-cond")
            cond_node.add_child(body_head)   # taken
            join = CFGNode("block", text="loop-join")
            body_tail.add_child(cond_node)   # back edge (conservative)
            cond_node.add_child(join)        # exit branch
            return cond_node, join
        # Compound statement
        if kind == cindex.CursorKind.COMPOUND_STMT:
            return build_from_compound(stmt_cursor)
        # Return
        if kind == cindex.CursorKind.RETURN_STMT:
            node = CFGNode("stmt", cursor=stmt_cursor, text="return")
            return node, node
        # Declaration or other statement: create simple stmt node
        node = CFGNode("stmt", cursor=stmt_cursor, text=str(stmt_cursor.kind).split('.')[-1])
        return node, node

    # build body
    block_head, block_tail = build_from_compound(body)
    entry.add_child(block_head)
    return entry

# ---------------------------------------------------------------------------
# Path-sensitive traversal and state machine
# State:
#   - sessions: dict var -> {'opened':True/False, 'opened_at': (file,line), 'closed':bool}
#   - job_handles: dict hjob -> {'started_at':(file,line), 'polled':bool}
#
# We'll explore paths using DFS; when a condition can be statically evaluated (simple int equality)
# we'll prune unreachable branches.
# ---------------------------------------------------------------------------
State = namedtuple('State', ['sessions', 'jobs', 'polls'])  # sessions: dict var->list(opened_at), jobs: dict hjob->{'started':..., 'polled':bool}, polls:list

def clone_state(s: State) -> State:
    return State(sessions={k:list(v) for k,v in s.sessions.items()},
                 jobs={k:dict(v) for k,v in s.jobs.items()},
                 polls=list(s.polls))

def is_condition_decidable(cursor) -> Optional[bool]:
    """Try to evaluate simple conditions like (i == 1) when i is constant in same function.
    Right now we don't do full interprocedural evaluation; return None if unknown.
    """
    try:
        txt = "".join([t.spelling for t in cursor.get_tokens()])
        # examples: (i==1) or (i == 0)
        m = re.search(r'([A-Za-z_]\w*)\s*(==|!=)\s*(-?\d+)', txt)
        if m:
            var = m.group(1)
            op = m.group(2)
            lit = int(m.group(3))
            # we don't maintain full symbol table — only detect literal comparisons like '0==0'
            # if var is a literal like '1' then evaluate
            if var.isdigit():
                val = int(var)
                if op == '==': return val == lit
                if op == '!=': return val != lit
        # check pure literal conditions '0' or '1'
        if re.fullmatch(r'\s*1\s*', txt):
            return True
        if re.fullmatch(r'\s*0\s*', txt):
            return False
    except Exception:
        pass
    return None

# ---------------------------------------------------------------------------
# Walk CFG and perform path-sensitive analysis; record issues found per file
# ---------------------------------------------------------------------------
class AnalyzerEngine:
    def __init__(self, max_sessions:int):
        self.max_sessions = max_sessions
        self.issues = defaultdict(list)   # file -> list of issue dict
        self.global_session_open_sites = {}  # var -> list of (file,line)

    def analyze_function(self, func_cursor, entry_node:CFGNode, file_map:Dict[str,str]):
        """Traverse CFG from entry_node and collect events per path."""
        # depth-first exploration with path state
        initial_state = State(sessions=defaultdict(list), jobs={}, polls=[])
        stack = [(entry_node, initial_state)]
        visited_paths = 0
        MAX_PATHS = 20000

        while stack:
            node, state = stack.pop()
            visited_paths += 1
            if visited_paths > MAX_PATHS:
                # prevent explosion
                break
            # process node
            if node.kind == "call":
                call_node = node.cursor
                cname = get_call_name(call_node)
                first_arg = extract_first_arg_from_call(call_node)
                hjob = extract_hjob_from_call(call_node)
                fileloc = (call_node.location.file.name if call_node.location and call_node.location.file else file_map.get(func_cursor.spelling, "<unknown>"), call_node.location.line if call_node.location else 0)
                # SESSION OPEN
                if cname in SESSION_OPEN_NAMES:
                    lhs = find_lhs_var_of_call(call_node)
                    # track open by variable
                    state.sessions[lhs].append(fileloc)
                    # also add to global sites for max-sessions check
                    self.global_session_open_sites.setdefault(lhs, []).append(fileloc)
                # SESSION CLOSE (sync)
                elif cname in SESSION_CLOSE_NAMES:
                    arg = first_arg
                    if arg in state.sessions and state.sessions[arg]:
                        state.sessions[arg].pop()  # close most recent
                # SESSION CLOSE ASYNC
                elif cname in SESSION_CLOSE_ASYNC_NAMES:
                    arg = first_arg
                    if arg in state.sessions and state.sessions[arg]:
                        # for async, mark close but require poll on returned hjob (later)
                        state.sessions[arg].pop()
                        # we can't map the returned hJob here (call site returns to var) via extract; but we can detect that CloseSessionAsync present and poll later
                        # record poll requirement as special job with key "async_close:<arg>:line"
                        marker = f"async_close:{arg}:{fileloc[1]}"
                        state.jobs[marker] = {"started": fileloc, "polled": False}
                # POLL
                elif cname in POLL_HANDLE_NAMES:
                    # mark hjob as polled (if exists)
                    arg = first_arg
                    if arg in state.jobs:
                        state.jobs[arg]['polled'] = True
                    # also mark any jobs named that var as polled
                    for k in list(state.jobs.keys()):
                        if k == arg:
                            state.jobs[k]['polled'] = True
                # JOB START
                elif cname in JOB_START_NAMES:
                    # record job handle; if hjob is None, we may not be able to track — but best-effort
                    if hjob:
                        # if same handle already started and not polled, this is an overwrite error (will be reported later when detecting)
                        state.jobs[hjob] = {"started": fileloc, "polled": False, "call": cname}
                    else:
                        # try to generate a synthetic handle key from call site
                        k = f"job_@{fileloc[0]}:{fileloc[1]}"
                        state.jobs[k] = {"started": fileloc, "polled": False, "call": cname}
                # other API not handled -> ignore
            # traverse children successors
            # branch pruning: if node is 'stmt' with a condition cursor, check decidability
            # Our build creates 'stmt' nodes for conditions with cursor referencing IF_STMT or loop.
            nexts = node.children
            if node.kind == "stmt" and node.cursor is not None:
                # attempt to decide condition for IF or loop nodes
                if node.text == "if-cond" or node.text == "loop-cond":
                    decidable = is_condition_decidable(node.cursor)
                    if decidable is True:
                        # choose first child (then branch) if exists
                        if nexts:
                            # push only then branch (we built then as first child)
                            stack.append((nexts[0], clone_state(state)))
                        continue
                    if decidable is False:
                        # choose else branch if exists (we built else as second child)
                        if len(nexts) > 1:
                            stack.append((nexts[1], clone_state(state)))
                        else:
                            # no else -> just continue with join: assume fall-through to child's first child's successor
                            if len(nexts) > 0:
                                stack.append((nexts[0], clone_state(state)))
                        continue
            # default: push all successors with copied state
            for succ in reversed(nexts):
                stack.append((succ, clone_state(state)))

            # If node has no successors (function end), evaluate state for issues
            if not nexts:
                # check job handles not polled
                for h, info in state.jobs.items():
                    if not info.get("polled", False):
                        start_file, start_line = info['started']
                        self.issues[start_file].append({
                            "level":"ERROR",
                            "type":"JOB_NOT_POLLED",
                            "message": f"Job handle '{h}' started at line {start_line} (call: {info.get('call')}) not polled on this path",
                            "line": start_line
                        })
                # check sessions left open
                for var, opens in state.sessions.items():
                    if opens:
                        for f,line in opens:
                            self.issues[f].append({
                                "level":"ERROR",
                                "type":"SESSION_LEAK",
                                "message": f"Session variable '{var}' opened at line {line} may remain open on this path",
                                "line": line
                            })
        # done function

    def finalize_global_checks(self):
        # Check potential active sessions count by counting unique session vars with open sites (conservative)
        active_vars = [v for v, sites in self.global_session_open_sites.items() if sites]
        if len(active_vars) > self.max_sessions:
            # attach to root (no specific file): create a global entry
            self.issues["<global>"].append({
                "level":"ERROR",
                "type":"GLOBAL_SESSION_LIMIT_VIOLATION",
                "message": f"Potential active sessions = {len(active_vars)} > allowed {self.max_sessions}",
                "line": 0
            })

# ---------------------------------------------------------------------------
# Utilities to parse files, index functions, build CFGs, and run analyzer
# ---------------------------------------------------------------------------
def collect_c_files(src_root: str) -> List[str]:
    lst = []
    for root, _, files in os.walk(src_root):
        for f in files:
            if f.lower().endswith((".c", ".h", ".cpp")):
                lst.append(os.path.join(root, f))
    return lst

def index_and_build(src_root: str, clang_args: List[str], max_sessions:int):
    index = cindex.Index.create()
    files = collect_c_files(src_root)
    if not files:
        print("[WARN] No C/C++ files found in", src_root)
    print(f"[INFO] Files to parse: {len(files)}")
    # map function name -> cursor
    func_map = {}
    func_file = {}
    # parse each file, collect diagnostics, functions
    tu_map = {}
    for f in files:
        print(f"[SCAN] {f}")
        try:
            tu = index.parse(f, args=clang_args)
        except Exception as e:
            print(f"[WARN] parse failed for {f} with args {clang_args}: {e}")
            try:
                tu = index.parse(f, args=[])
            except Exception as e2:
                print(f"[ERROR] parse fallback failed for {f}: {e2}")
                continue
        tu_map[f] = tu
        # print diagnostics
        for d in tu.diagnostics:
            # severity mapping: 1=Error,2=Warning,3=Note etc.
            sev = "ERROR" if d.severity == 3 else ("WARNING" if d.severity == 2 else "NOTE")
            loc = f"{d.location.file}:{d.location.line}" if d.location and d.location.file else f
            print(f"[DIAG] {sev} {loc}: {d.spelling}")
        # collect functions
        for node in tu.cursor.get_children():
            if node.kind == cindex.CursorKind.FUNCTION_DECL and node.spelling:
                func_map[node.spelling] = node
                func_file[node.spelling] = f
    # build CFGs
    cfg_map = {}
    for fname, fnode in func_map.items():
        try:
            cfg_entry = build_cfg_for_function(fnode)
            cfg_map[fname] = cfg_entry
        except Exception as e:
            print(f"[WARN] building CFG for {fname} failed: {e}")
    # analyze
    engine = AnalyzerEngine(max_sessions=max_sessions)
    for fname, entry in cfg_map.items():
        fcursor = func_map[fname]
        engine.analyze_function(fcursor, entry, func_file)
    engine.finalize_global_checks()
    return engine, files

# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="CycurHSM Advanced CFG static analyzer")
    parser.add_argument("src", help="path to source folder (contains .c/.h)")
    parser.add_argument("--clang-args", nargs="*", default=[], help="extra args passed to libclang (e.g. -Ipath)")
    parser.add_argument("--max-sessions", type=int, default=5, help="max concurrent host sessions (for global check)")
    parser.add_argument("--output-html", default="hsm_report.html")
    parser.add_argument("--output-json", default="hsm_report.json")
    args = parser.parse_args()

    # auto-add clang builtin include for Conda environment to fix stdint etc.
    conda_prefix = os.environ.get("CONDA_PREFIX", "")
    builtin_include = None
    if conda_prefix:
        try:
            # find clang version dir
            cand = os.path.join(conda_prefix, "Library", "lib", "clang")
            if os.path.isdir(cand):
                versions = sorted(os.listdir(cand), reverse=True)
                for v in versions:
                    ip = os.path.join(cand, v, "include")
                    if os.path.isdir(ip):
                        builtin_include = ip
                        break
        except Exception:
            builtin_include = None
    final_clang_args = list(args.clang_args)
    if builtin_include:
        final_clang_args.insert(0, "-I" + builtin_include)
        print(f"[INFO] Adding builtin include: {builtin_include}")
    # ensure src path exists
    if not os.path.isdir(args.src):
        print(f"[ERROR] source folder {args.src} not found")
        sys.exit(1)

    engine, files = index_and_build(args.src, final_clang_args, args.max_sessions)

    # prepare report data
    files_report = []
    total_issues = 0
    for f in files:
        iss = engine.issues.get(f, [])
        files_report.append({"path": os.path.relpath(f, args.src), "issues": iss})
        total_issues += len(iss)
    # include global issues
    global_issues = engine.issues.get("<global>", [])
    for g in global_issues:
        files_report.append({"path": "<global>", "issues":[g]})
        total_issues += 1

    # write json
    summary = {
        "repo": os.path.abspath(args.src),
        "files_scanned": len(files),
        "total_issues": total_issues,
        "files": files_report
    }
    with open(args.output_json, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)

    # render html
    tpl = Template(HTML_TMPL)
    html = tpl.render(repo=os.path.abspath(args.src), files_scanned=len(files), total_issues=total_issues, files=files_report)
    with open(args.output_html, "w", encoding="utf-8") as hf:
        hf.write(html)

    print(f"[OK] HTML report: {args.output_html}")
    print(f"[OK] JSON report: {args.output_json}")
    print(f"[OK] files scanned: {len(files)}, issues: {total_issues}")

if __name__ == "__main__":
    main()
