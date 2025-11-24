#!/usr/bin/env python3
"""
hsm_analyzer_advanced.py

CycurHSM static analyzer with:
  - Path-sensitive analysis (branch-aware)
  - Simple value-range / constant propagation for int-like variables
  - Loop bound detection for simple for/while patterns
  - Dead-branch pruning for obvious impossible conditions

Detects (focused on your 5.1.6.x cases):
  1) Exceeding session limit (OpenSession in loops with bound > max-sessions AND
     global "live session" count > max_sessions at any point)
  2) Session handle overwrite (s = OpenSession(); s = OpenSession(); leak)
  3) Reusing a busy session for a new job (one active job per session)

Also:
  - Tracks wrapper functions that call CloseSession / CloseSessionAsync / PollHandle
  - Works across multiple source files (same TU per file)
  - HTML / JSON reporting
"""

import os
import sys
import argparse
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from clang import cindex

# ============================================================
#  libclang loader
# ============================================================

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
    python hsm_analyzer_advanced.py <source-folder>
""")

load_libclang()

from clang.cindex import CursorKind, TranslationUnit

# ============================================================
#  HSM API configuration
# ============================================================

SESSION_OPEN_NAMES: Set[str] = {"ecy_hsm_Csai_OpenSession"}
SESSION_CLOSE_NAMES: Set[str] = {"ecy_hsm_Csai_CloseSession"}
SESSION_CLOSE_ASYNC_NAMES: Set[str] = {"ecy_hsm_Csai_CloseSessionAsync"}
POLL_HANDLE_NAMES: Set[str] = {"ecy_hsm_Csai_PollHandle"}

# Job-triggering APIs
JOB_START_NAMES: Set[str] = {
    "ecy_hsm_Csai_HashStart",
    "ecy_hsm_Csai_HashFast",
    "ecy_hsm_Csai_Update",
    "ecy_hsm_Csai_Finish",
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

ALL_INTERESTING_NAMES: Set[str] = (
    SESSION_OPEN_NAMES
    | SESSION_CLOSE_NAMES
    | SESSION_CLOSE_ASYNC_NAMES
    | POLL_HANDLE_NAMES
    | JOB_START_NAMES
)

# ============================================================
#  Abstract values & program state
# ============================================================

class AbstractKind:
    UNKNOWN = "UNKNOWN"
    CONST   = "CONST"
    INTERVAL = "INTERVAL"

@dataclass
class AbstractValue:
    kind: str = AbstractKind.UNKNOWN
    cval: Optional[int] = None
    lo: Optional[int] = None
    hi: Optional[int] = None

    @staticmethod
    def unknown():
        return AbstractValue(AbstractKind.UNKNOWN)

    @staticmethod
    def const(k: int):
        return AbstractValue(AbstractKind.CONST, cval=k)

    @staticmethod
    def interval(lo: int, hi: int):
        if lo == hi:
            return AbstractValue.const(lo)
        return AbstractValue(AbstractKind.INTERVAL, lo=lo, hi=hi)

    def copy(self):
        return AbstractValue(self.kind, self.cval, self.lo, self.hi)

    def __str__(self):
        if self.kind == AbstractKind.UNKNOWN:
            return "?"
        if self.kind == AbstractKind.CONST:
            return f"{self.cval}"
        return f"[{self.lo},{self.hi}]"

    def add_const(self, k: int):
        if self.kind == AbstractKind.CONST:
            return AbstractValue.const(self.cval + k)
        if self.kind == AbstractKind.INTERVAL:
            return AbstractValue.interval(self.lo + k, self.hi + k)
        return AbstractValue.unknown()

@dataclass
class ProgramState:
    # value analysis
    vars: Dict[str, AbstractValue] = field(default_factory=dict)

    # session/job state per variable
    session_open_vars: Dict[str, bool] = field(default_factory=dict)
    session_open_line: Dict[str, int] = field(default_factory=dict)
    session_job_handle: Dict[str, str] = field(default_factory=dict)
    session_job_start_line: Dict[str, int] = field(default_factory=dict)

    # handle-ID based session tracking (kept for leaks / extra checks)
    var_to_handle: Dict[str, int] = field(default_factory=dict)
    handle_live: Dict[int, bool] = field(default_factory=dict)
    next_handle_id: int = 1

    # CURRENT concurrency tracking
    live_sessions: int = 0
    max_live_sessions: int = 0

    def copy(self) -> "ProgramState":
        return ProgramState(
            vars={k: v.copy() for k, v in self.vars.items()},
            session_open_vars=dict(self.session_open_vars),
            session_open_line=dict(self.session_open_line),
            session_job_handle=dict(self.session_job_handle),
            session_job_start_line=dict(self.session_job_start_line),
            var_to_handle=dict(self.var_to_handle),
            handle_live=dict(self.handle_live),
            next_handle_id=self.next_handle_id,
            live_sessions=self.live_sessions,
            max_live_sessions=self.max_live_sessions,
        )

# ============================================================
#  Issues & function summaries
# ============================================================

@dataclass
class HSMIssue:
    level: str   # ERROR/WARN/INFO
    type: str
    message: str
    file: str
    line: int
    func: str

@dataclass
class FunctionSummary:
    close_param_indices: Set[int] = field(default_factory=set)
    poll_param_indices: Set[int] = field(default_factory=set)

# ============================================================
#  Analyzer
# ============================================================

class RepoAnalyzer:
    def __init__(self, root: str, max_sessions: int, clang_args: List[str]):
        self.root = os.path.abspath(root)
        self.max_sessions = max_sessions
        self.clang_args = clang_args
        self.index = cindex.Index.create()
        self.files_scanned = 0
        self.issues: List[HSMIssue] = []

        # wrapper summaries (close(s), pollJob(h))
        self.func_summaries: Dict[str, FunctionSummary] = {}

    # ----------------- High-level run ------------------------

    def run(self):
        files = self._collect_sources()
        self.files_scanned = len(files)
        if not files:
            print(f"[WARN] No C/C++ files found under {self.root}")
            return

        print(f"[INFO] Found {len(files)} files to analyze")

        # Pass 1: build wrapper summaries
        for path in files:
            tu = self._parse_tu(path)
            if tu is None:
                continue
            self._collect_summaries_from_tu(tu)

        # Pass 2: analyze each TU function
        for path in files:
            tu = self._parse_tu(path)
            if tu is None:
                continue
            self._analyze_tu(tu)

    def _collect_sources(self) -> List[str]:
        out = []
        for r, _, fs in os.walk(self.root):
            for f in fs:
                if f.endswith((".c", ".h", ".cpp", ".cc", ".cxx")):
                    out.append(os.path.join(r, f))
        return out

    def _parse_tu(self, path: str) -> Optional[TranslationUnit]:
        try:
            return self.index.parse(path, args=self.clang_args)
        except Exception as e:
            print(f"[ERROR] Failed to parse {path}: {e}")
            return None

    # ========================================================
    #  Pass 1: wrapper summaries
    # ========================================================

    def _collect_summaries_from_tu(self, tu: TranslationUnit):
        for cursor in tu.cursor.get_children():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                self._collect_summary_for_function(cursor)

    def _collect_summary_for_function(self, func_cursor):
        name = func_cursor.spelling
        if not name:
            return
        params = list(func_cursor.get_arguments())
        if not params:
            return

        summary = FunctionSummary()

        def visit(node):
            if node.kind == CursorKind.CALL_EXPR:
                callee_name = self._get_call_name(node)
                if callee_name in SESSION_CLOSE_NAMES or callee_name in SESSION_CLOSE_ASYNC_NAMES:
                    arg0 = self._arg_to_param_index(node, 0, params)
                    if arg0 is not None:
                        summary.close_param_indices.add(arg0)
                elif callee_name in POLL_HANDLE_NAMES:
                    arg0 = self._arg_to_param_index(node, 0, params)
                    if arg0 is not None:
                        summary.poll_param_indices.add(arg0)
            for ch in node.get_children():
                visit(ch)

        for ch in func_cursor.get_children():
            if ch.kind == CursorKind.COMPOUND_STMT:
                visit(ch)

        if summary.close_param_indices or summary.poll_param_indices:
            self.func_summaries[name] = summary
            print(f"[SUM] wrapper {name}: close={summary.close_param_indices} poll={summary.poll_param_indices}")

    def _arg_to_param_index(self, call_cursor, arg_index: int, params) -> Optional[int]:
        args = list(call_cursor.get_arguments())
        if arg_index >= len(args):
            return None
        arg = args[arg_index]
        ref = arg.referenced or arg
        if ref.kind == CursorKind.PARM_DECL:
            for i, p in enumerate(params):
                if p == ref:
                    return i
        return None

    # ========================================================
    #  Pass 2: per-function analysis
    # ========================================================

    def _analyze_tu(self, tu: TranslationUnit):
        for cursor in tu.cursor.get_children():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                self._analyze_function(cursor)

    def _analyze_function(self, func_cursor):
        func_name = func_cursor.spelling or "<anon>"
        init_state = ProgramState()

        def analyze_stmt(node, state: ProgramState, in_loop: bool, loop_bound: int) -> List[ProgramState]:
            if node is None:
                return [state]

            kind = node.kind
            children = list(node.get_children())

            # Compound: execute children in sequence, propagate states
            if kind == CursorKind.COMPOUND_STMT:
                states = [state]
                for ch in children:
                    new_states = []
                    for st in states:
                        new_states.extend(analyze_stmt(ch, st, in_loop, loop_bound))
                    states = new_states
                return states

            # Variable declaration with initializer
            if kind == CursorKind.VAR_DECL:
                name = node.spelling
                if children:
                    val = self._eval_expr(children[-1], state)
                    state.vars[name] = val
                else:
                    state.vars[name] = AbstractValue.unknown()
                return [state]

            # Binary operator: handle simple assignments a = expr;
            if kind == CursorKind.BINARY_OPERATOR:
                txt = self._tokens_to_str(node)
                m = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*(.+)", txt)
                children = list(node.get_children())

                # Value-propagation for plain assignments (unchanged)
                if m:
                    lhs_name = m.group(1)
                    rhs_expr = children[-1] if children else None
                    val = self._eval_expr(rhs_expr, state) if rhs_expr else AbstractValue.unknown()
                    state.vars[lhs_name] = val

                # Special case: LHS = HSM_API_CALL(...)
                if len(children) == 2 and children[1].kind == CursorKind.CALL_EXPR:
                    call_node = children[1]
                    callee_name = self._get_call_name(call_node)
                    if callee_name in ALL_INTERESTING_NAMES:
                        lhs_name = self._var_name(children[0])
                        # Call handler with explicit LHS override so overwrite detection works
                        self._handle_call(func_name, call_node, state, in_loop, loop_bound, lhs_override=lhs_name)
                        return [state]

                # Default: still analyze children so other calls inside are seen
                states = [state]
                for ch in children:
                    new_states = []
                    for st in states:
                        new_states.extend(analyze_stmt(ch, st, in_loop, loop_bound))
                    states = new_states
                return states

            # If statement
            if kind == CursorKind.IF_STMT:
                if not children:
                    return [state]
                cond = children[0]
                then_node = children[1] if len(children) > 1 else None
                else_node = children[2] if len(children) > 2 else None

                cond_result = self._eval_condition(cond, state)
                out_states: List[ProgramState] = []

                if cond_result != "FALSE" and then_node is not None:
                    then_state = state.copy()
                    out_states.extend(analyze_stmt(then_node, then_state, in_loop, loop_bound))

                if cond_result != "TRUE" and else_node is not None:
                    else_state = state.copy()
                    out_states.extend(analyze_stmt(else_node, else_state, in_loop, loop_bound))

                if not out_states:
                    out_states.append(state)
                return out_states

            # For loop (approximate)
            if kind == CursorKind.FOR_STMT:
                lb = self._estimate_for_bound(node, state)
                body = None
                for ch in children:
                    if ch.kind == CursorKind.COMPOUND_STMT:
                        body = ch
                        break
                if body is not None:
                    start_live = state.live_sessions
                    body_state = state.copy()
                    analyze_stmt(body, body_state, in_loop=True, loop_bound=lb if lb is not None else -1)

                    delta = body_state.live_sessions - start_live
                    if lb is not None and delta > 0:
                        potential = state.live_sessions + delta * lb
                        if potential > self.max_sessions:
                            fpath, line = self._loc(node.location)
                            self._emit_issue(
                                "ERROR",
                                "SESSION_LIMIT_EXCEEDED_LOOP",
                                f"For-loop may create up to {potential} concurrent sessions "
                                f"(> max_sessions={self.max_sessions}) "
                                f"(per-iteration delta={delta}, iterations={lb}).",
                                fpath, line, func_name
                            )

                return [state]

            # While / Do-while: approximate similarly (one iteration)
            if kind in (CursorKind.WHILE_STMT, CursorKind.DO_STMT):
                lb = self._estimate_while_bound(node, state)
                body = None
                for ch in children:
                    if ch.kind == CursorKind.COMPOUND_STMT:
                        body = ch
                        break
                if body is not None:
                    _ = analyze_stmt(body, state.copy(), True, lb if lb is not None else -1)
                return [state]

            # Call expression
            if kind == CursorKind.CALL_EXPR:
                self._handle_call(func_name, node, state, in_loop, loop_bound)
                return [state]

            # Default: descend
            states = [state]
            for ch in children:
                new_states = []
                for st in states:
                    new_states.extend(analyze_stmt(ch, st, in_loop, loop_bound))
                states = new_states
            return states

        # start from function body
        for ch in func_cursor.get_children():
            if ch.kind == CursorKind.COMPOUND_STMT:
                analyze_stmt(ch, init_state, in_loop=False, loop_bound=-1)

    # ========================================================
    #  Call handling (HSM logic)
    # ========================================================

    def _handle_call(self,
                     func_name: str,
                     call_cursor,
                     state: ProgramState,
                     in_loop: bool,
                     loop_bound: int,
                     lhs_override: Optional[str] = None):
        file_path, line = self._loc(call_cursor.location)
        callee_name = self._get_call_name(call_cursor)
        args = list(call_cursor.get_arguments())

        # 1) SESSION OPEN (ecy_hsm_Csai_OpenSession)
        if callee_name in SESSION_OPEN_NAMES:
            # Use explicit LHS if provided (from BINARY_OPERATOR), otherwise try to infer it
            lhs = lhs_override if lhs_override is not None else self._get_assignment_lhs(call_cursor)

            # ----- Robust overwrite detection -----
            if lhs:
                # If this variable was previously assigned a handle, and that handle is still live → overwrite
                old_handle = state.var_to_handle.get(lhs)
                if old_handle is not None and state.handle_live.get(old_handle, False):
                    old_line = state.session_open_line.get(lhs, 0)
                    self._emit_issue(
                        "ERROR",
                        "SESSION_HANDLE_OVERWRITE",
                        f"Variable '{lhs}' already holds an active session opened at line {old_line}. "
                        f"Overwritten by new OpenSession() at line {line}. Previous session is leaked.",
                        file_path,
                        line,
                        func_name
                    )

            # ----- Normal OpenSession behavior (unchanged logic) -----
            if lhs:
                # Mark variable as holding an active open session
                state.session_open_vars[lhs] = True
                state.session_open_line[lhs] = line

                # Assign new handle ID
                new_handle = state.next_handle_id
                state.next_handle_id += 1
                state.var_to_handle[lhs] = new_handle
                state.handle_live[new_handle] = True

                # Increment live session count
                state.live_sessions += 1
                state.max_live_sessions = max(state.max_live_sessions, state.live_sessions)
            else:
                # OpenSession() without assignment; count as a live session
                state.live_sessions += 1
                state.max_live_sessions = max(state.max_live_sessions, state.live_sessions)

            # ----- Global session limit check (unchanged) -----
            if state.live_sessions > self.max_sessions:
                self._emit_issue(
                    "ERROR",
                    "SESSION_LIMIT_EXCEEDED",
                    f"Potentially {state.live_sessions} concurrent sessions "
                    f"(> configured max_sessions={self.max_sessions}).",
                    file_path,
                    line,
                    func_name
                )

            return

        # 2) SESSION CLOSE / ASYNC CLOSE
        if callee_name in SESSION_CLOSE_NAMES or callee_name in SESSION_CLOSE_ASYNC_NAMES:
            if args:
                sess_name = self._var_name(args[0])
                if sess_name:
                    # mark var as closed (best-effort)
                    state.session_open_vars[sess_name] = False

                    # BEST-EFFORT live counter: always decrement by 1 if > 0
                    if state.live_sessions > 0:
                        state.live_sessions -= 1

                    # optional: mark handle dead (for leak / debug – does NOT affect live_sessions)
                    hid = state.var_to_handle.get(sess_name)
                    if hid is not None and state.handle_live.get(hid, False):
                        state.handle_live[hid] = False
            return

        # 3) PollHandle
        if callee_name in POLL_HANDLE_NAMES:
            if args:
                h = self._var_name(args[0])
                if h:
                    for s, hj in list(state.session_job_handle.items()):
                        if hj == h:
                            state.session_job_handle[s] = ""
            return

        # 4) Job start APIs (one active job per session)
        if callee_name in JOB_START_NAMES:
            if not args:
                return
            sess = self._var_name(args[0])
            hjob = self._extract_hjob_from_call(call_cursor)
            if sess:
                current_h = state.session_job_handle.get(sess, "")
                if current_h:
                    start_line = state.session_job_start_line.get(sess, 0)
                    self._emit_issue(
                        "ERROR", "SESSION_REUSE_WITH_ACTIVE_JOB",
                        f"Session '{sess}' already has active job handle '{current_h}' "
                        f"started at line {start_line}. New job {callee_name} started "
                        "without polling/completing previous job.",
                        file_path, line, func_name
                    )
                state.session_job_handle[sess] = hjob or "<unknown>"
                state.session_job_start_line[sess] = line
            return

        # 5) Wrapper functions
        summary = self.func_summaries.get(callee_name)
        if summary:
            # emulate close / poll on parameters
            for idx in summary.close_param_indices:
                if idx < len(args):
                    sess = self._var_name(args[idx])
                    if sess:
                        state.session_open_vars[sess] = False
                        if state.live_sessions > 0:
                            state.live_sessions -= 1
            for idx in summary.poll_param_indices:
                if idx < len(args):
                    h = self._var_name(args[idx])
                    if h:
                        for s, hj in list(state.session_job_handle.items()):
                            if hj == h:
                                state.session_job_handle[s] = ""
            return

    # ========================================================
    #  Expression & condition evaluation
    # ========================================================

    def _eval_expr(self, expr_cursor, state: ProgramState) -> AbstractValue:
        if expr_cursor is None:
            return AbstractValue.unknown()
        k = expr_cursor.kind

        # Integer literal
        if k == CursorKind.INTEGER_LITERAL:
            txt = self._tokens_to_str(expr_cursor)
            try:
                return AbstractValue.const(int(txt, 0))
            except ValueError:
                return AbstractValue.unknown()

        # Decl ref => var
        if k == CursorKind.DECL_REF_EXPR:
            name = expr_cursor.spelling
            return state.vars.get(name, AbstractValue.unknown())

        # Unary operator, e.g. -1
        if k == CursorKind.UNARY_OPERATOR:
            txt = self._tokens_to_str(expr_cursor)
            try:
                return AbstractValue.const(int(txt, 0))
            except ValueError:
                return AbstractValue.unknown()

        # Binary operator
        if k == CursorKind.BINARY_OPERATOR:
            txt = self._tokens_to_str(expr_cursor)
            try:
                return AbstractValue.const(int(txt, 0))
            except ValueError:
                pass
            m = re.match(r"\s*([A-Za-z_]\w*)\s*([\+\-])\s*(-?\d+)\s*$", txt)
            if m:
                var_name = m.group(1)
                op = m.group(2)
                k_val = int(m.group(3))
                base = state.vars.get(var_name, AbstractValue.unknown())
                if op == "-":
                    k_val = -k_val
                return base.add_const(k_val)

        return AbstractValue.unknown()

    def _eval_condition(self, cond_cursor, state: ProgramState) -> str:
        """
        Return "TRUE", "FALSE", "UNKNOWN"
        Try:
          - constant 0 / non-zero
          - var == const, var != const, var < const, etc.
        """
        if cond_cursor is None:
            return "UNKNOWN"
        txt = self._tokens_to_str(cond_cursor).strip()

        try:
            v = int(txt, 0)
            return "FALSE" if v == 0 else "TRUE"
        except ValueError:
            pass

        m = re.match(r"^\s*([A-Za-z_]\w*)\s*(==|!=|<|>|<=|>=)\s*(-?\d+)\s*$", txt)
        if m:
            vname = m.group(1)
            op = m.group(2)
            k = int(m.group(3))
            av = state.vars.get(vname, AbstractValue.unknown())
            if av.kind == AbstractKind.CONST:
                x = av.cval
                res = None
                if op == "==":
                    res = (x == k)
                elif op == "!=":
                    res = (x != k)
                elif op == "<":
                    res = (x < k)
                elif op == "<=":
                    res = (x <= k)
                elif op == ">":
                    res = (x > k)
                elif op == ">=":
                    res = (x >= k)
                if res is True:
                    return "TRUE"
                if res is False:
                    return "FALSE"
        return "UNKNOWN"

    # ========================================================
    #  Loop bound estimation helpers
    # ========================================================

    def _estimate_for_bound(self, for_cursor, state: ProgramState) -> Optional[int]:
        """
        Try to estimate iteration count for simple patterns like:
            for (int i = 0; i < N; i++)
            for (i = 0; i <= N; i++)
            for (i = 0; N > i; i++)
            etc.

        This version first uses the AST (VarDecl) to get the loop variable
        and its initial constant value, then falls back to the original
        text-based regex logic if needed.
        """
        children = list(for_cursor.get_children())
        if len(children) < 2:
            return None
        init = children[0]
        cond = children[1]
        inc = children[2] if len(children) > 2 else None

        # ---------- NEW: AST-based extraction for "for (int i = 0; ...)" ----------
        var = None
        start_val = None

        # Handle DeclStmt / VarDecl as in: for (int i = 0; ... )
        if init.kind in (CursorKind.DECL_STMT, CursorKind.VAR_DECL):
            var_decl = None
            if init.kind == CursorKind.VAR_DECL:
                var_decl = init
            else:  # DECL_STMT
                for ch in init.get_children():
                    if ch.kind == CursorKind.VAR_DECL:
                        var_decl = ch
                        break

            if var_decl is not None:
                var = var_decl.spelling
                v_children = list(var_decl.get_children())
                if v_children:
                    init_expr = v_children[-1]
                    av = self._eval_expr(init_expr, state)
                    if av.kind == AbstractKind.CONST:
                        start_val = av.cval

        # ---------- FALLBACK: original text-based logic ----------
        if var is None or start_val is None:
            init_txt = self._tokens_to_str(init)
            m = re.search(r"([A-Za-z_]\w*)\s*=\s*(-?\d+)", init_txt)
            if not m:
                return None
            var = m.group(1)
            try:
                start_val = int(m.group(2), 0)
            except ValueError:
                return None

        # Condition text (unchanged logic)
        cond_txt = self._tokens_to_str(cond)
        m2 = re.search(rf"{re.escape(var)}\s*<\s*(-?\d+)", cond_txt)
        inclusive = False
        if not m2:
            m2 = re.search(rf"{re.escape(var)}\s*<=\s*(-?\d+)", cond_txt)
            inclusive = True
        if not m2:
            m2 = re.search(r"(-?\d+)\s*>\s*" + re.escape(var), cond_txt)
            inclusive = False
            if not m2:
                m2 = re.search(r"(-?\d+)\s*>=\s*" + re.escape(var), cond_txt)
                inclusive = True
        if not m2:
            return None
        try:
            bound_val = int(m2.group(1), 0)
        except ValueError:
            return None

        # Increment pattern (unchanged logic)
        if inc is not None:
            inc_txt = self._tokens_to_str(inc)
            if not re.search(
                rf"{re.escape(var)}\s*(\+\+|--|[+\-]=\s*1|=\s*{re.escape(var)}\s*\+\s*1|=\s*{re.escape(var)}\s*-\s*1)",
                inc_txt
            ):
                return None

        # Iteration count (unchanged logic)
        if inclusive:
            iters = max(0, bound_val - start_val + 1)
        else:
            iters = max(0, bound_val - start_val)
        return iters

    def _estimate_while_bound(self, while_cursor, state: ProgramState) -> Optional[int]:
        children = list(while_cursor.get_children())
        if not children:
            return None
        cond = children[0]
        cond_txt = self._tokens_to_str(cond)
        m = re.match(r"\s*([A-Za-z_]\w*)\s*<\s*(-?\d+)", cond_txt)
        if not m:
            return None
        var = m.group(1)
        try:
            bound = int(m.group(2), 0)
        except ValueError:
            return None
        av = state.vars.get(var)
        if av and av.kind == AbstractKind.CONST:
            return max(0, bound - av.cval)
        return None

    # ========================================================
    #  Small helpers
    # ========================================================

    def _tokens_to_str(self, cursor) -> str:
        return "".join(t.spelling for t in cursor.get_tokens())

    def _get_call_name(self, call_cursor) -> str:
        """
        Robust call name resolution.

        Strategy:
          1. Try normal libclang resolution (referenced.spelling).
          2. Fallback to cursor.spelling.
          3. FINAL fallback: scan tokens and:
             - if any token exactly matches one of our known HSM API names,
               return that.
             - otherwise, return the first identifier-looking token.
        """
        # 1) libclang's normal resolution
        callee = call_cursor.referenced
        if callee and callee.spelling:
            return callee.spelling

        # 2) cursor spelling
        if call_cursor.spelling:
            return call_cursor.spelling

        # 3) token-based fallback
        first_ident = ""
        for t in call_cursor.get_tokens():
            tok = t.spelling
            # Prefer exact known HSM API names even if they are not the first identifier
            if tok in ALL_INTERESTING_NAMES:
                return tok
            # Remember first identifier-looking token as a fallback
            if not first_ident and re.match(r"[A-Za-z_]\w*$", tok):
                first_ident = tok

        return first_ident

    def _loc(self, location) -> Tuple[str, int]:
        if not location or not location.file:
            return ("<unknown>", 0)
        return (location.file.name, location.line)

    def _var_name(self, expr_cursor) -> str:
        """
        ALWAYS return stable variable names including array subscripts:
            session[i]  → "session[i]"
            session[0]  → "session[0]"
        """

        if expr_cursor is None:
            return ""

        kind = expr_cursor.kind

        # ARRAY_SUBSCRIPT_EXPR  → handle "session[i]"
        if kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            ch = list(expr_cursor.get_children())
            if len(ch) == 2:
                base = self._var_name(ch[0])
                index = self._tokens_to_str(ch[1])   # includes 'i' literal or number
                return f"{base}[{index}]"
            # fallback
            return self._var_name(ch[0])

        # Normal identifiers
        ref = expr_cursor.referenced or expr_cursor
        if ref.spelling:
            return ref.spelling

        # Token fallback
        for t in expr_cursor.get_tokens():
            if re.match(r"[A-Za-z_]\w*$", t.spelling):
                return t.spelling

        return ""

    def _get_assignment_lhs(self, call_cursor) -> Optional[str]:
        """
        Extract correct LHS for:
            s = OpenSession();
            session[i] = OpenSession();
            session[i+j] = OpenSession();
        EVEN WHEN Windows libclang does NOT produce ARRAY_SUBSCRIPT_EXPR.
        """

        parent = call_cursor.semantic_parent

        # --- CASE 1: Standard assignment via BINARY_OPERATOR
        if parent and parent.kind == CursorKind.BINARY_OPERATOR:
            full = self._tokens_to_str(parent)

            # Normalize whitespace
            full = full.replace(" ", "")
            # Example: "session[i]=ecy_hsm_Csai_OpenSession();"

            # Split at '='
            parts = full.split("=", 1)
            if len(parts) == 2:
                lhs = parts[0]
                return lhs  # ALWAYS includes array text, perfect for our use case

        # --- CASE 2: VAR_DECL
        if parent and parent.kind == CursorKind.VAR_DECL:
            # This catches: ecy_hsm_Csai_session_t s = OpenSession();
            return parent.spelling

        # --- CASE 3: Token fallback (100% reliable)
        tokens = list(parent.get_tokens()) if parent else list(call_cursor.get_tokens())

        eq_pos = None
        for idx, t in enumerate(tokens):
            if t.spelling == "=":
                eq_pos = idx
                break

        if eq_pos is None:
            return None

        lhs_text = "".join(tok.spelling for tok in tokens[:eq_pos]).strip()
        # This yields EXACTLY:
        # "session[i]" or "session[i+1]" or "session [ i ]"

        return lhs_text or None

    def _extract_hjob_from_call(self, call_cursor) -> Optional[str]:
        for arg in call_cursor.get_arguments():
            if arg.kind == CursorKind.UNARY_OPERATOR:
                ch = list(arg.get_children())
                if ch:
                    return self._var_name(ch[0])
        return None

    def _emit_issue(self, level: str, itype: str, msg: str,
                    file_path: str, line: int, func_name: str):
        self.issues.append(HSMIssue(level, itype, msg, file_path, line, func_name))

# ============================================================
#  Reporting
# ============================================================

def write_json(path: str, issues: List[HSMIssue]) -> bool:
    data = []
    for i in issues:
        data.append({
            "level": i.level,
            "type": i.type,
            "message": i.message,
            "file": i.file,
            "line": i.line,
            "function": i.func,
        })
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"[ERROR] Writing JSON {path}: {e}")
        return False

def escape_html(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))

def write_html(path: str, issues: List[HSMIssue]) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CycurHSM Static Analysis Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #1b3b5a; }
    table { width:100%; border-collapse: collapse; }
    th, td { border:1px solid #ddd; padding:4px 6px; font-size:13px; }
    th { background:#eef; }
    tr.ERROR { background:#ffecec; }
    tr.WARN  { background:#fff6e5; }
    tr.INFO  { background:#eef7ff; }
  </style>
</head>
<body>
<h1>CycurHSM Static Analysis Report</h1>
<table>
<thead>
<tr><th>File</th><th>Line</th><th>Function</th><th>Level</th><th>Type</th><th>Message</th></tr>
</thead>
<tbody>
""")
            for i in issues:
                f.write(f'<tr class="{i.level}">')
                f.write(f"<td>{escape_html(i.file)}</td>")
                f.write(f"<td>{i.line}</td>")
                f.write(f"<td>{escape_html(i.func)}</td>")
                f.write(f"<td>{escape_html(i.level)}</td>")
                f.write(f"<td>{escape_html(i.type)}</td>")
                f.write(f"<td>{escape_html(i.message)}</td>")
                f.write("</tr>\n")
            f.write("""</tbody>
</table>
</body>
</html>
""")
        return True
    except Exception as e:
        print(f"[ERROR] Writing HTML {path}: {e}")
        return False

# ============================================================
#  CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CycurHSM advanced static analyzer "
                    "(session limit, handle overwrite, busy session reuse)")
    parser.add_argument("src",
                        help="Source folder (repo root) or single file")
    parser.add_argument("--max-sessions", type=int, default=6,
                        help="Configured maximum allowed sessions")
    parser.add_argument("--clang-args", nargs="*", default=[],
                        help="Extra clang args, e.g. -Iinclude -Ifake_headers")
    parser.add_argument("--json-out", default="",
                        help="Optional JSON report path")
    parser.add_argument("--html-out", default="",
                        help="Optional HTML report path")

    args = parser.parse_args()
    src_path = os.path.abspath(args.src)
    if not os.path.exists(src_path):
        print(f"[FATAL] Source path does not exist: {src_path}")
        sys.exit(1)

    if os.path.isfile(src_path):
        root = os.path.dirname(src_path)
    else:
        root = src_path

    analyzer = RepoAnalyzer(root=root,
                            max_sessions=args.max_sessions,
                            clang_args=args.clang_args)
    analyzer.run()

    print("=====================================================")
    print(f"[SUMMARY] Files scanned: {analyzer.files_scanned}")
    print(f"[SUMMARY] Total issues : {len(analyzer.issues)}")
    print("=====================================================")
    for issue in analyzer.issues:
        print(f"{issue.file}:{issue.line} [{issue.level}] {issue.type} "
              f"in {issue.func}: {issue.message}")

    if args.json_out:
        if write_json(args.json_out, analyzer.issues):
            print(f"[OK] JSON report: {args.json_out}")
    if args.html_out:
        if write_html(args.html_out, analyzer.issues):
            print(f"[OK] HTML report: {args.html_out}")

if __name__ == "__main__":
    main()
