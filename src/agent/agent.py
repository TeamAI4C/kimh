"""
Takes CodeQL sequential JSON + RAG context → produces a clean Unified Diff.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"


# ---------------------------------------------------------------------------
# Prompt loader
# ---------------------------------------------------------------------------

def _load_prompt(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text()


# ---------------------------------------------------------------------------
# Diff extractor / sanitizer
# ---------------------------------------------------------------------------

_DIFF_HEADER_RE = re.compile(r"^---\s+a/", re.MULTILINE)
_FENCED_DIFF_RE = re.compile(
    r"```(?:diff)?\s*\n(---\s+a/.*?)```", re.DOTALL
)


def extract_diff(raw: str) -> str:
    """Extract a clean Unified Diff from the LLM's raw response.

    Strips markdown fences, conversational filler, and any text before/after
    the actual diff content.
    """
    raw = raw.strip()

    # Case 1: response is wrapped in markdown code fences
    m = _FENCED_DIFF_RE.search(raw)
    if m:
        return m.group(1).strip()

    # Case 2: raw text starts with the diff header already
    m = _DIFF_HEADER_RE.search(raw)
    if m:
        return raw[m.start():].strip()

    # Case 3: ERROR sentinel
    if raw.startswith("ERROR:"):
        return raw

    # Fallback: return as-is and let the caller validate
    return raw


def validate_diff(diff_text: str, allowed_files: list[str] | None = None) -> list[str]:
    """Return a list of validation warnings (empty = all good)."""
    warnings: list[str] = []

    if not _DIFF_HEADER_RE.search(diff_text):
        warnings.append("No valid '--- a/' header found in diff output.")

    if "@@ " not in diff_text:
        warnings.append("No @@ hunk header found.")

    # Check for hallucinated paths
    if allowed_files:
        for line in diff_text.splitlines():
            if line.startswith("--- a/"):
                path = line[6:].strip()
                if path not in allowed_files:
                    warnings.append(f"Hallucinated file path: {path}")
            elif line.startswith("+++ b/"):
                path = line[6:].strip()
                if path not in allowed_files:
                    warnings.append(f"Hallucinated file path: {path}")

    return warnings


# ---------------------------------------------------------------------------
# LLM Agent
# ---------------------------------------------------------------------------

class PatchAgent:
    """Wraps the LLM with system prompt, template injection, and diff parsing."""

    def __init__(
        self,
        provider: str = "anthropic",
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.0,
        max_tokens: int = 8192,
        anthropic_api_key: str | None = None,
        openai_api_key: str | None = None,
    ):
        if provider == "anthropic":
            api_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "Anthropic API key not found. Set ANTHROPIC_API_KEY env var "
                    "or agent.anthropic_api_key in config/settings.yaml."
                )
            self.llm = ChatAnthropic(
                model=model, temperature=temperature,
                max_tokens=max_tokens, api_key=api_key,
            )
        elif provider == "openai":
            api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "OpenAI API key not found. Set OPENAI_API_KEY env var "
                    "or agent.openai_api_key in config/settings.yaml."
                )
            self.llm = ChatOpenAI(
                model=model, temperature=temperature,
                max_tokens=max_tokens, api_key=api_key,
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        self.system_prompt = _load_prompt("system.txt")
        self.analysis_template = _load_prompt("analysis_template.txt")
        self.feedback_template = _load_prompt("feedback_template.txt")

    # -- primary generation -------------------------------------------------

    def generate_patch(
        self,
        codeql_json: list[dict[str, Any]],
        rag_context: str,
        source_code: str,
        language_name: str = "C/C++",
        code_fence: str = "c",
    ) -> str:
        """Generate the first-attempt Unified Diff."""
        user_msg = (
            self.analysis_template
            .replace("{{CODEQL_JSON_RESULT}}", json.dumps(codeql_json, indent=2))
            .replace("{{RAG_CONTEXT}}", rag_context)
            .replace("{{SOURCE_CODE}}", source_code)
            .replace("{{LANGUAGE_NAME}}", language_name)
            .replace("{{CODE_FENCE}}", code_fence)
        )

        response = self.llm.invoke([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=user_msg),
        ])

        raw = response.content
        logger.debug("Raw LLM response:\n%s", raw)

        return extract_diff(raw)

    # -- feedback-driven retry ----------------------------------------------

    def regenerate_patch(
        self,
        error_type: str,
        error_log: str,
        codeql_json: list[dict[str, Any]],
        previous_diff: str,
    ) -> str:
        """Send the error back to the LLM and ask for a corrected patch."""
        user_msg = (
            self.feedback_template
            .replace("{{ERROR_TYPE}}", error_type)
            .replace("{{ERROR_LOG}}", error_log)
            .replace("{{CODEQL_JSON_RESULT}}", json.dumps(codeql_json, indent=2))
            .replace("{{PREVIOUS_DIFF}}", previous_diff)
        )

        response = self.llm.invoke([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=user_msg),
        ])

        return extract_diff(response.content)


# ---------------------------------------------------------------------------
# Helper: format RAG hits for prompt injection
# ---------------------------------------------------------------------------

def format_rag_context(hits: list[dict[str, Any]]) -> str:
    """Turn RAG query results into a readable block for the prompt."""
    if not hits:
        return "(No relevant historical patches found.)"

    parts: list[str] = []
    for i, hit in enumerate(hits, 1):
        meta = hit.get("metadata", {})
        parts.append(
            f"### Match {i}  (CVE: {meta.get('cve_id', 'N/A')}, "
            f"type: {meta.get('vuln_type', 'N/A')}, "
            f"distance: {hit.get('distance', 'N/A'):.4f})\n\n"
            f"{hit.get('document', '')}"
        )
    return "\n\n---\n\n".join(parts)
