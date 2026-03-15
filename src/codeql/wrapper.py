"""
Phase 2 – CodeQL CLI wrapper.

Automates:  compile target  →  create DB  →  run query  →  parse SARIF  →  sequential JSON.

Supports multi-language analysis via language profiles and CodeQL built-in
security query packs.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from src.lang_detect import LanguageProfile, detect_or_resolve

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FlowStep:
    """One node in a dataflow chain."""
    step: int
    action: str            # "allocate" | "free" | "use" | "copy" | "taint-source" …
    file: str
    line: int
    column: int
    snippet: str           # source code at that location
    variable: str = ""
    message_text: str = "" # SARIF location.message.text (e.g. "ControlFlowNode for password")

@dataclass
class AnalysisResult:
    """Complete chain for one finding."""
    rule_id: str
    severity: str
    message: str
    chain: list[FlowStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "chain": [asdict(s) for s in self.chain],
        }


# ---------------------------------------------------------------------------
# CodeQL CLI wrapper
# ---------------------------------------------------------------------------

class CodeQLRunner:
    """Drive the CodeQL CLI from Python."""

    def __init__(
        self,
        cli_path: str = "codeql",
        language: str = "auto",
        query_dir: str = "src/codeql/queries",
        threads: int = 4,
        timeout: int = 600,
        query_mode: str = "pack",
        build_command: str | None = None,
    ):
        self.cli = cli_path
        self.language = language
        self.query_dir = Path(query_dir)
        self.threads = threads
        self.timeout = timeout
        self.query_mode = query_mode        # "pack" | "custom"
        self.build_command = build_command   # explicit build command, or None for auto

    # -- helpers ------------------------------------------------------------

    def _run(self, args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
        cmd = [self.cli] + args
        logger.info("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            cwd=cwd,
        )
        if result.returncode != 0:
            logger.error("CodeQL stderr:\n%s", result.stderr)
            raise RuntimeError(f"CodeQL failed (rc={result.returncode}): {result.stderr[:500]}")
        return result

    # -- public pipeline ----------------------------------------------------

    def create_database(
        self,
        source_root: str | Path,
        db_path: str | Path,
        profile: LanguageProfile | None = None,
    ) -> Path:
        """Create a CodeQL database from a source tree.

        Build mode is determined by the language profile:
        - ``none``: no build command (Python, JS, Ruby)
        - ``autobuild``: CodeQL handles the build automatically (Go, Java, Swift)
        - ``manual``: explicit build command required (C/C++)
        """
        source_root = Path(source_root).resolve()
        db_path = Path(db_path).resolve()

        if db_path.exists():
            logger.info("DB already exists at %s – skipping creation", db_path)
            return db_path

        if profile is None:
            profile = detect_or_resolve(source_root, self.language)

        args = [
            "database", "create",
            str(db_path),
            f"--language={profile.codeql_language}",
            f"--source-root={source_root}",
            f"--threads={self.threads}",
            "--overwrite",
        ]

        if profile.build_mode == "manual":
            cmd = self.build_command or "make"
            args.append(f"--command={cmd}")
        # For "none" and "autobuild": no --command flag

        try:
            self._run(args)
        except RuntimeError:
            if profile.build_mode == "manual":
                logger.warning(
                    "Build command failed — falling back to --build-mode=none "
                    "(source-only extraction, reduced interprocedural accuracy)"
                )
                # Remove the failed partial DB
                import shutil
                if db_path.exists():
                    shutil.rmtree(db_path)
                # Retry without a build command
                args_none = [
                    "database", "create",
                    str(db_path),
                    f"--language={profile.codeql_language}",
                    f"--source-root={source_root}",
                    f"--threads={self.threads}",
                    "--overwrite",
                    "--build-mode=none",
                ]
                self._run(args_none)
            else:
                raise
        return db_path

    def run_query(self, db_path: str | Path, query_file: str | None = None) -> Path:
        """Run a QL query against the database. Returns path to SARIF output."""
        db_path = Path(db_path).resolve()
        sarif_out = Path(tempfile.mktemp(suffix=".sarif"))

        if query_file is None:
            query_file = str(self.query_dir / "uaf_dataflow.ql")

        self._run([
            "database", "analyze",
            str(db_path),
            query_file,
            "--format=sarifv2.1.0",
            f"--output={sarif_out}",
            f"--threads={self.threads}",
        ])
        return sarif_out

    def compile_query(
        self,
        query_file: str | Path,
        *,
        cwd: str | Path | None = None,
    ) -> tuple[bool, str]:
        """Compile a QL query and return (success, combined_output)."""
        cmd = [self.cli, "query", "compile", str(Path(query_file).resolve())]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            cwd=str(cwd) if cwd else None,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        combined = "\n".join(x for x in (out, err) if x).strip()
        return proc.returncode == 0, combined

    def run_all_queries(
        self,
        db_path: str | Path,
        profile: LanguageProfile | None = None,
    ) -> list[Path]:
        """Run queries against the database.

        In ``pack`` mode: run the built-in CodeQL security-and-quality query pack
        plus the security-experimental suite for maximum coverage.  Results from
        both runs are returned as separate SARIF files and merged downstream.

        In ``custom`` mode: run every local ``.ql`` file in ``query_dir``
        (backward-compatible with the original C/C++-only pipeline).
        """
        if self.query_mode == "pack" and profile is not None:
            db_path = Path(db_path).resolve()
            sarifs: list[Path] = []

            # 1. Primary suite (security-and-quality)
            sarif_main = Path(tempfile.mktemp(suffix="-main.sarif"))
            self._run([
                "database", "analyze",
                str(db_path),
                profile.query_pack,
                "--format=sarifv2.1.0",
                f"--output={sarif_main}",
                f"--threads={self.threads}",
            ])
            sarifs.append(sarif_main)

            # 2. Experimental suite (additional memory/security queries)
            experimental_pack = profile.query_pack.replace(
                "-security-and-quality.qls", "-security-experimental.qls"
            ).replace(
                "-security-extended.qls", "-security-experimental.qls"
            )
            if experimental_pack != profile.query_pack:
                try:
                    sarif_exp = Path(tempfile.mktemp(suffix="-experimental.sarif"))
                    self._run([
                        "database", "analyze",
                        str(db_path),
                        experimental_pack,
                        "--format=sarifv2.1.0",
                        f"--output={sarif_exp}",
                        f"--threads={self.threads}",
                    ])
                    sarifs.append(sarif_exp)
                    logger.info("Experimental suite completed: %s", sarif_exp)
                except Exception as exc:
                    logger.warning("Experimental suite failed (non-fatal): %s", exc)

            return sarifs

        # custom mode: run each .ql file individually
        sarifs_custom: list[Path] = []
        for ql in sorted(self.query_dir.glob("*.ql")):
            sarifs_custom.append(self.run_query(db_path, str(ql)))
        return sarifs_custom

    # -- SARIF → sequential JSON -------------------------------------------

    @staticmethod
    def parse_sarif(
        sarif_path: str | Path,
        language: str | None = None,
    ) -> list[AnalysisResult]:
        """Parse a SARIF file into a list of AnalysisResult with sequential chains."""
        sarif_path = Path(sarif_path)
        with open(sarif_path) as f:
            sarif = json.load(f)

        results: list[AnalysisResult] = []

        for run in sarif.get("runs", []):
            # Build a rule-id → severity map
            rules = {
                r["id"]: r.get("defaultConfiguration", {}).get("level", "error")
                for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            }

            for finding in run.get("results", []):
                rule_id = finding.get("ruleId", "unknown")
                severity = rules.get(rule_id, "error")
                message = finding.get("message", {}).get("text", "")

                chain: list[FlowStep] = []

                # Extract codeFlows (path-problem results)
                for code_flow in finding.get("codeFlows", []):
                    for thread_flow in code_flow.get("threadFlows", []):
                        tf_locs = thread_flow.get("locations", [])
                        total_steps = len(tf_locs)
                        for idx, loc_obj in enumerate(tf_locs):
                            loc = loc_obj.get("location", {})
                            phys = loc.get("physicalLocation", {})
                            art = phys.get("artifactLocation", {}).get("uri", "")
                            region = phys.get("region", {})

                            snippet_text = (
                                region.get("snippet", {}).get("text", "").strip()
                            )
                            msg_text = loc.get("message", {}).get("text", "")

                            is_last = (idx == total_steps - 1) and total_steps > 1
                            action = _infer_action(
                                snippet_text, idx, language,
                                message_text=msg_text,
                                rule_id=rule_id,
                                is_last_step=is_last,
                            )

                            chain.append(FlowStep(
                                step=idx + 1,
                                action=action,
                                file=art,
                                line=region.get("startLine", 0),
                                column=region.get("startColumn", 0),
                                snippet=snippet_text,
                                message_text=msg_text,
                            ))

                # Fallback: use the primary location if no codeFlows
                if not chain:
                    loc = finding.get("locations", [{}])[0]
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {}).get("uri", "")
                    region = phys.get("region", {})

                    # Use rule_id sink map for single-step findings
                    action = _RULE_SINK_MAP.get(rule_id, "finding")

                    chain.append(FlowStep(
                        step=1,
                        action=action,
                        file=art,
                        line=region.get("startLine", 0),
                        column=region.get("startColumn", 0),
                        snippet=region.get("snippet", {}).get("text", "").strip(),
                    ))

                results.append(AnalysisResult(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    chain=chain,
                ))

        return results

    # -- convenience --------------------------------------------------------

    def analyze(
        self,
        source_root: str | Path,
        db_path: str | Path,
    ) -> tuple[list[dict[str, Any]], LanguageProfile]:
        """Full pipeline: detect language → create DB → run queries → return sequential JSON.

        Returns a tuple of (results_list, language_profile).
        """
        profile = detect_or_resolve(source_root, self.language)
        logger.info("Detected language: %s", profile.display_name)

        db = self.create_database(source_root, db_path, profile)
        sarif_paths = self.run_all_queries(db, profile)

        all_results: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        for sp in sarif_paths:
            for ar in self.parse_sarif(sp, language=profile.codeql_language):
                d = ar.to_dict()
                # Deduplicate across suites by (rule_id, file, line)
                chain = d.get("chain", [])
                if chain:
                    key = f"{d['rule_id']}:{chain[0].get('file','')}:{chain[0].get('line',0)}"
                else:
                    key = f"{d['rule_id']}:{d['message']}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_results.append(d)
                else:
                    logger.debug("Deduplicated finding: %s", key)

        return all_results, profile


# ---------------------------------------------------------------------------
# Heuristic to label each step in the chain (multi-language)
# ---------------------------------------------------------------------------

_ACTION_KEYWORDS_CPP: dict[str, str] = {
    "my_alloc":      "allocate",        # custom allocator wrapper
    "my_free":       "free",            # custom deallocator wrapper
    "SAFE_FREE":     "sanitized-free",  # macro sanitizer (free + NULL)
    "indirect call": "indirect-call",   # function pointer indirect call
    "->":            "field-access",    # struct field access via pointer
    "malloc":        "allocate",
    "calloc":        "allocate",
    "realloc":       "allocate",
    "free":          "free",
    "strcpy":        "unsafe-copy",
    "strcat":        "unsafe-copy",
    "sprintf":       "unsafe-copy",
    "sscanf":        "unsafe-copy",
    "printf":        "use",
    # I/O source functions (must precede shorter substrings like "gets")
    "fgets":         "taint-source",
    "fread":         "taint-source",
    "read(":         "taint-source",
    "recv(":         "taint-source",
    "recvfrom":      "taint-source",
    "getenv":        "taint-source",
    "getline":       "taint-source",
    "scanf(":        "taint-source",
    "gets(":         "unsafe-copy",
}

_ACTION_KEYWORDS_PYTHON: dict[str, str] = {
    "eval(":       "code-execution",
    "exec(":       "code-execution",
    "subprocess":  "command-execution",
    "os.system":   "command-execution",
    "os.popen":    "command-execution",
    "pickle.load": "deserialization",
    "yaml.load":   "deserialization",
    "open(":       "file-access",
    "request.":    "taint-source",
    "input(":      "taint-source",
    "execute(":    "sql-sink",
    "cursor.":     "sql-sink",
}

_ACTION_KEYWORDS_JS: dict[str, str] = {
    "innerHTML":     "xss-sink",
    "document.write": "xss-sink",
    "eval(":         "code-execution",
    "child_process": "command-execution",
    "exec(":         "command-execution",
    "spawn(":        "command-execution",
    "req.body":      "taint-source",
    "req.query":     "taint-source",
    "req.params":    "taint-source",
    "query(":        "sql-sink",
    "fs.":           "file-access",
}

_ACTION_KEYWORDS_JAVA: dict[str, str] = {
    "Runtime.exec":       "command-execution",
    "ProcessBuilder":     "command-execution",
    "Statement.execute":  "sql-sink",
    "prepareStatement":   "sql-sink",
    "getParameter":       "taint-source",
    "getInputStream":     "taint-source",
    "ObjectInputStream":  "deserialization",
    "readObject":         "deserialization",
    "FileInputStream":    "file-access",
    "new File(":          "file-access",
}

_ACTION_KEYWORDS_GO: dict[str, str] = {
    "exec.Command":  "command-execution",
    "os.Open":       "file-access",
    "http.Get":      "taint-source",
    "r.FormValue":   "taint-source",
    "r.URL.Query":   "taint-source",
    "db.Query":      "sql-sink",
    "db.Exec":       "sql-sink",
    "template.HTML": "xss-sink",
    "fmt.Fprintf":   "use",
}

_ACTION_KEYWORDS_RUST: dict[str, str] = {
    "Command::new":  "command-execution",
    "File::open":    "file-access",
    "unsafe":        "unsafe-block",
    "from_raw":      "unsafe-cast",
}

_LANG_KEYWORDS: dict[str | None, dict[str, str]] = {
    None:         _ACTION_KEYWORDS_CPP,    # default fallback
    "cpp":        _ACTION_KEYWORDS_CPP,
    "python":     _ACTION_KEYWORDS_PYTHON,
    "javascript": _ACTION_KEYWORDS_JS,
    "java":       _ACTION_KEYWORDS_JAVA,
    "go":         _ACTION_KEYWORDS_GO,
    "rust":       _ACTION_KEYWORDS_RUST,
}


# ---------------------------------------------------------------------------
# Chain summarization – compress long chains for LLM consumption
# ---------------------------------------------------------------------------

_KEY_ACTIONS = frozenset({
    "source", "taint-source", "allocate", "free", "use",
    "unsafe-copy", "sql-sink", "code-execution", "command-execution",
    "xss-sink", "deserialization", "file-access", "finding",
    "sanitized-free", "indirect-call", "field-access",
})


def summarize_chain(chain: list[dict], max_steps: int = 6) -> list[dict]:
    """Compress a long chain to *max_steps* or fewer entries.

    Strategy:
    1. First step (source) and last step (sink) are always preserved.
    2. Intermediate steps whose ``action`` is in ``_KEY_ACTIONS`` are preserved.
    3. Consecutive non-key (``intermediate``) steps are collapsed into a single
       summary node that records how many steps and files were elided.
    4. If the preserved count still exceeds *max_steps*, middle key-action
       steps are dropped (keeping first and last) until the limit is met.
    """
    if len(chain) <= max_steps:
        return chain

    # -- 1. Tag each step as "keep" or "collapse" --------------------------
    first = chain[0]
    last = chain[-1]
    middle = chain[1:-1]

    kept: list[dict] = []       # key-action steps from the middle
    run: list[dict] = []        # current run of intermediate steps

    def _flush_run() -> None:
        """Convert accumulated intermediate run into a summary node."""
        if not run:
            return
        files = {s.get("file", "") for s in run}
        files.discard("")
        kept.append({
            "step": 0,          # renumbered later
            "action": "intermediate",
            "file": "(summarized)",
            "line": 0,
            "snippet": f"… {len(run)} intermediate steps across {len(files) or 1} file(s) …",
        })
        run.clear()

    for step in middle:
        if step.get("action", "intermediate") in _KEY_ACTIONS:
            _flush_run()
            kept.append(step)
        else:
            run.append(step)
    _flush_run()

    # -- 2. Assemble: first + kept + last ----------------------------------
    result = [first] + kept + [last]

    # -- 3. Trim to max_steps if still too long ----------------------------
    if len(result) > max_steps:
        middle_budget = max_steps - 2
        mid = result[1:-1]
        # Prioritize key-action nodes over summary nodes
        key_mid = [s for s in mid if s.get("action") in _KEY_ACTIONS]
        summary_mid = [s for s in mid if s.get("action") not in _KEY_ACTIONS]
        if len(key_mid) <= middle_budget:
            # Keep all key-action nodes, fill remainder with summary nodes
            remaining = middle_budget - len(key_mid)
            mid = key_mid + summary_mid[:remaining]
        else:
            # Too many key-action nodes: pick evenly-spaced ones
            indices = [round(i * (len(key_mid) - 1) / (middle_budget - 1)) for i in range(middle_budget)] if middle_budget > 1 else [0]
            mid = [key_mid[i] for i in dict.fromkeys(indices)]
        result = [first] + mid[:middle_budget] + [last]

    # -- 4. Renumber steps sequentially ------------------------------------
    for i, step in enumerate(result):
        step["step"] = i + 1

    return result


# ---------------------------------------------------------------------------
# Rule-ID → sink type mapping (CodeQL security query rule IDs)
# ---------------------------------------------------------------------------

_RULE_SINK_MAP: dict[str, str] = {
    # SQL injection
    "py/sql-injection":         "sql-sink",
    "java/sql-injection":       "sql-sink",
    "js/sql-injection":         "sql-sink",
    "go/sql-injection":         "sql-sink",
    "rb/sql-injection":         "sql-sink",
    # Code injection / execution
    "py/code-injection":        "code-execution",
    "java/code-injection":      "code-execution",
    "js/code-injection":        "code-execution",
    "py/unsafe-deserialization": "deserialization",
    "java/unsafe-deserialization": "deserialization",
    # Command injection
    "py/command-line-injection":  "command-execution",
    "java/command-line-injection":"command-execution",
    "js/command-line-injection":  "command-execution",
    "go/command-line-injection":  "command-execution",
    # XSS
    "py/reflective-xss":       "xss-sink",
    "js/xss":                   "xss-sink",
    "java/xss":                 "xss-sink",
    # Path traversal / file access
    "py/path-injection":        "file-access",
    "java/path-injection":      "file-access",
    "js/path-injection":        "file-access",
    "cpp/path-injection":       "file-access",
    # SSRF
    "py/full-ssrf":             "ssrf-sink",
    "java/ssrf":                "ssrf-sink",
    # LDAP injection
    "py/ldap-injection":        "ldap-sink",
    "java/ldap-injection":      "ldap-sink",
    # XXE
    "java/xxe":                 "xxe-sink",
    "py/xxe":                   "xxe-sink",
    # Log injection
    "py/log-injection":         "log-sink",
    "java/log-injection":       "log-sink",
    # Weak crypto (informational sinks)
    "py/weak-sensitive-data-hashing": "weak-hash-sink",
    "py/insecure-protocol":          "insecure-protocol-sink",
    # Memory safety (C/C++)
    "cpp/use-after-free":       "use",
    "cpp/buffer-overflow":      "unsafe-copy",
    "cpp/double-free":          "free",
    "cpp/overflow-static":      "unsafe-copy",
    "cpp/new-free-mismatch":    "free",
    "cpp/new-array-delete-mismatch": "free",
    "cpp/new-delete-array-mismatch": "free",
    "cpp/incorrect-check-scanf": "unsafe-copy",
    "cpp/missing-check-scanf":  "unsafe-copy",
    "cpp/unbounded-write":      "unsafe-copy",
    "cpp/overrunning-write":    "unsafe-copy",
    "cpp/overflow-buffer":      "unsafe-copy",
    "cpp/return-stack-allocated-memory": "use",
    "cpp/using-expired-stack-address": "use",
    "cpp/dangerous-function-overflow": "unsafe-copy",
    "cpp/uninitialized-local":  "use",
    "cpp/suspicious-sizeof":    "unsafe-copy",
    # Experimental memory queries
    "cpp/alloc-multiplication-overflow": "unsafe-copy",
    "cpp/memory-unsafe-function-scan": "unsafe-copy",
    "cpp/buffer-access-incorrect-length": "unsafe-copy",
    # File/permission safety
    "cpp/world-writable-file-creation": "file-access",
    "cpp/potentially-dangerous-function": "unsafe-copy",
    "cpp/wrong-type-format-argument": "unsafe-copy",
    "cpp/lossy-pointer-cast": "unsafe-copy",
}

# Source indicators from SARIF message.text patterns
_SOURCE_MESSAGE_KEYWORDS = [
    "getparameter", "getinputstream", "request", "formvalue",
    "user input", "tainted", "untrusted", "remote",
]


def _infer_action(
    snippet: str,
    idx: int,
    language: str | None = None,
    *,
    message_text: str = "",
    rule_id: str = "",
    is_last_step: bool = False,
) -> str:
    """Best-effort action label from snippet, message text, and rule context.

    Inference priority:
    1. Keyword match in snippet (most specific)
    2. Keyword match in message_text (SARIF location.message.text)
    3. Rule-ID-based sink inference for the last step in a chain
    4. Fallback: first step → "source", others → "intermediate"
    """
    keywords = _LANG_KEYWORDS.get(language, _ACTION_KEYWORDS_CPP)

    # 1. Snippet keyword match
    if snippet:
        for keyword, action in keywords.items():
            if keyword in snippet:
                return action

    # 2. Message text keyword match (e.g. "ControlFlowNode for eval()")
    if message_text:
        msg_lower = message_text.lower()
        for keyword, action in keywords.items():
            if keyword.lower() in msg_lower:
                return action
        # Check for source indicators in message
        if idx == 0:
            for src_kw in _SOURCE_MESSAGE_KEYWORDS:
                if src_kw in msg_lower:
                    return "taint-source"

    # 3. Rule-ID sink inference for last step
    if is_last_step and rule_id:
        sink_action = _RULE_SINK_MAP.get(rule_id)
        if sink_action:
            return sink_action

    # 4. Fallback
    return "intermediate" if idx > 0 else "source"


# ---------------------------------------------------------------------------
# Re-inference: re-run action labeling after snippet enrichment
# ---------------------------------------------------------------------------

def re_infer_actions(
    results: list[dict[str, Any]],
    language: str | None = None,
) -> list[dict[str, Any]]:
    """Re-run action inference on results that now have enriched snippets.

    Should be called AFTER _enrich_snippets() fills in empty snippet fields.
    Only re-labels steps that are still "source" (idx==0 fallback) or
    "intermediate" (fallback), since those were likely assigned by fallback.
    """
    for result in results:
        chain = result.get("chain", [])
        rule_id = result.get("rule_id", "")
        total_steps = len(chain)
        for idx, step in enumerate(chain):
            old_action = step.get("action", "intermediate")
            # Only re-infer fallback labels
            if old_action not in ("source", "intermediate"):
                continue
            snippet = step.get("snippet", "")
            msg_text = step.get("message_text", "")
            is_last = (idx == total_steps - 1) and total_steps > 1
            new_action = _infer_action(
                snippet, idx, language,
                message_text=msg_text,
                rule_id=rule_id,
                is_last_step=is_last,
            )
            step["action"] = new_action
    return results


# ---------------------------------------------------------------------------
# Source-sink chain filtering
# ---------------------------------------------------------------------------

_SOURCE_ACTIONS = frozenset({
    "source", "taint-source",
})

_DANGEROUS_SINK_ACTIONS = frozenset({
    "sql-sink", "code-execution", "command-execution", "xss-sink",
    "deserialization", "file-access", "unsafe-copy", "use", "free",
    "ssrf-sink", "ldap-sink", "xxe-sink", "log-sink",
    "weak-hash-sink", "insecure-protocol-sink",
})


def has_source_and_sink(chain: list[dict[str, Any]]) -> bool:
    """Check if a chain has at least one source AND one dangerous sink."""
    actions = {step.get("action", "") for step in chain}
    has_source = bool(actions & _SOURCE_ACTIONS)
    has_sink = bool(actions & _DANGEROUS_SINK_ACTIONS)
    return has_source and has_sink


def filter_source_sink_chains(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep only findings with exploitable dataflow chains.

    Acceptance criteria (any one is sufficient):
    1. Multi-step chain (2+ steps) from a codeFlow — CodeQL already performed
       source→sink dataflow tracking, so we trust these chains.
    2. Single-step finding with a dangerous action (e.g. point findings like
       ``code-execution`` from rule inference).

    Single-step ``finding`` actions without a dangerous sink are dropped — they
    are pattern-match-only results without dataflow evidence.
    """
    filtered: list[dict[str, Any]] = []
    for r in results:
        chain = r.get("chain", [])
        if not chain:
            continue
        # Multi-step: CodeQL tracked dataflow through codeFlows → trust it
        if len(chain) > 1:
            filtered.append(r)
            continue
        # Single-step: keep only if action itself is a dangerous sink
        action = chain[0].get("action", "")
        if action in _DANGEROUS_SINK_ACTIONS:
            filtered.append(r)
            continue
        logger.debug(
            "Filtered out finding %s: single-step non-dangerous action '%s'",
            r.get("rule_id", "?"),
            action,
        )
    return filtered


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse, yaml
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Run CodeQL analysis on a source tree.",
        prog="python -m src.codeql.wrapper",
    )
    parser.add_argument("source_root", help="Path to source tree")
    parser.add_argument("db_path", help="Path for CodeQL database")
    parser.add_argument(
        "--language", "-l", default=None,
        help="Language override (default: from config or auto)",
    )
    args = parser.parse_args()

    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)["codeql"]

    runner = CodeQLRunner(
        cli_path=cfg["cli_path"],
        language=args.language or cfg.get("language", "auto"),
        query_dir=cfg.get("custom_query_dir", cfg.get("query_suite", "src/codeql/queries")),
        threads=cfg["threads"],
        timeout=cfg["timeout_seconds"],
        query_mode=cfg.get("query_mode", "pack"),
        build_command=cfg.get("build_command"),
    )
    results, profile = runner.analyze(args.source_root, args.db_path)
    print(f"Language: {profile.display_name}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
