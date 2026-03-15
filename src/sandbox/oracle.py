"""
Phase 4 – PoV Sandbox Oracle.

Spins up a Docker container with ASAN-enabled compilation (C/C++),
or runs project tests for other languages, and captures the verdict.

Verification strategies:
  - ``asan``: C/C++ compile + ASAN + PoV (original behavior)
  - ``test_runner``: Apply patch + run project tests (Python, JS, Ruby)
  - ``build_and_test``: Build + test (Java, Go, Rust)
  - ``skip``: No verification
"""

from __future__ import annotations

import logging
import tempfile
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import docker
from docker.errors import ContainerError, ImageNotFound

from src.lang_detect import LanguageProfile

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    CRASH = "crash"                  # ASAN detected a bug  (exit != 0)
    PASS = "pass"                    # clean run  (exit == 0)
    COMPILE_ERROR = "compile_error"  # gcc/g++ failed  (exit == 3)
    PATCH_ERROR = "patch_error"      # patch -p1 failed  (exit == 2)
    TIMEOUT = "timeout"              # container exceeded time limit
    TEST_FAILURE = "test_failure"    # project tests failed
    SKIPPED = "skipped"              # verification skipped
    UNKNOWN = "unknown"


@dataclass
class OracleResult:
    verdict: Verdict
    exit_code: int
    stdout: str
    stderr: str
    asan_report: str           # extracted ASAN-specific lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "stdout_tail": self.stdout[-2000:] if self.stdout else "",
            "stderr_tail": self.stderr[-2000:] if self.stderr else "",
            "asan_report": self.asan_report,
        }


# ---------------------------------------------------------------------------
# Oracle driver
# ---------------------------------------------------------------------------

class SandboxOracle:
    """Control Docker containers to compile + run targets with ASAN,
    or to run project-level tests for multi-language support."""

    IMAGE_TAG = "findvuln-sandbox:latest"
    MULTILANG_IMAGE_PREFIX = "findvuln-sandbox-"
    DOCKERFILE_DIR = Path(__file__).parent / "docker"

    def __init__(
        self,
        timeout: int = 120,
        asan_flags: str = "-fsanitize=address -fno-omit-frame-pointer -g",
        compiler: str = "gcc",
        verification_strategy: str = "auto",
    ):
        self.client = None
        self.timeout = timeout
        self.asan_flags = asan_flags
        self.compiler = compiler
        self.verification_strategy = verification_strategy

    def _get_client(self):
        if self.client is None:
            self.client = docker.from_env()
        return self.client

    # -- Image management ---------------------------------------------------

    def build_image(self, force: bool = False) -> None:
        """Build the C/C++ ASAN sandbox Docker image."""
        client = self._get_client()
        try:
            client.images.get(self.IMAGE_TAG)
            if not force:
                logger.info("Image %s already exists.", self.IMAGE_TAG)
                return
        except ImageNotFound:
            pass

        logger.info("Building sandbox image from %s …", self.DOCKERFILE_DIR)
        client.images.build(
            path=str(self.DOCKERFILE_DIR),
            tag=self.IMAGE_TAG,
            rm=True,
        )
        logger.info("Image built: %s", self.IMAGE_TAG)

    def _build_multilang_image(
        self,
        language_profile: LanguageProfile,
        force: bool = False,
    ) -> str:
        """Build a multi-language Docker image for the given language."""
        tag = f"{self.MULTILANG_IMAGE_PREFIX}{language_profile.codeql_language}:latest"
        client = self._get_client()

        try:
            client.images.get(tag)
            if not force:
                logger.info("Image %s already exists.", tag)
                return tag
        except ImageNotFound:
            pass

        dockerfile_path = self.DOCKERFILE_DIR / "Dockerfile.multilang"
        if not dockerfile_path.exists():
            raise FileNotFoundError(
                f"Multi-language Dockerfile not found: {dockerfile_path}"
            )

        logger.info("Building multi-lang image %s …", tag)
        client.images.build(
            path=str(self.DOCKERFILE_DIR),
            dockerfile="Dockerfile.multilang",
            tag=tag,
            buildargs={"LANG": language_profile.codeql_language},
            rm=True,
        )
        logger.info("Image built: %s", tag)
        return tag

    # -- Core run -----------------------------------------------------------

    def run(
        self,
        source_file: str | Path | None = None,
        pov_file: str | Path | None = None,
        patch_file: str | Path | None = None,
        extra_files: dict[str, str | Path] | None = None,
        language_profile: LanguageProfile | None = None,
        project_root: str | Path | None = None,
        custom_test_command: str | None = None,
        custom_run_command: str | None = None,
    ) -> OracleResult:
        """Run the sandbox verification.

        Dispatches to the appropriate strategy based on language profile
        and configuration.
        """
        strategy = self._resolve_strategy(language_profile)

        if strategy == "skip":
            return OracleResult(
                verdict=Verdict.SKIPPED,
                exit_code=0,
                stdout="Verification skipped.",
                stderr="",
                asan_report="",
            )

        if strategy == "asan":
            return self._run_asan(source_file, pov_file, patch_file, extra_files, custom_run_command)

        if strategy in ("test_runner", "build_and_test"):
            return self._run_project_tests(
                project_root=project_root,
                patch_file=patch_file,
                language_profile=language_profile,
                custom_test_command=custom_test_command,
            )

        # Fallback: unknown strategy → skip
        logger.warning("Unknown verification strategy %r, skipping.", strategy)
        return OracleResult(
            verdict=Verdict.SKIPPED,
            exit_code=0,
            stdout=f"Unknown strategy: {strategy}",
            stderr="",
            asan_report="",
        )

    def _resolve_strategy(self, profile: LanguageProfile | None) -> str:
        """Determine which verification strategy to use."""
        if self.verification_strategy != "auto":
            return self.verification_strategy
        if profile is None:
            return "asan"
        return profile.sandbox_strategy

    # -- ASAN strategy (C/C++) ----------------------------------------------

    def _run_asan(
        self,
        source_file: str | Path | None,
        pov_file: str | Path | None,
        patch_file: str | Path | None,
        extra_files: dict[str, str | Path] | None,
        custom_run_command: str | None = None,
    ) -> OracleResult:
        """Original C/C++ ASAN verification pipeline."""
        self.build_image()

        staging = Path(tempfile.mkdtemp(prefix="findvuln_"))
        try:
            return self._run_asan_inner(staging, source_file, pov_file, patch_file, extra_files, custom_run_command)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _run_asan_inner(
        self,
        staging: Path,
        source_file: str | Path | None,
        pov_file: str | Path | None,
        patch_file: str | Path | None,
        extra_files: dict[str, str | Path] | None,
        custom_run_command: str | None = None,
    ) -> OracleResult:
        # Copy source
        src = Path(source_file)
        dest_src = staging / src.name
        shutil.copy2(src, dest_src)

        # Copy PoV
        env = {
            "COMPILER": self.compiler,
            "ASAN_FLAGS": self.asan_flags,
            "SRC_FILE": f"/workspace/{src.name}",
            "BINARY_NAME": "target",
        }

        if pov_file:
            pov = Path(pov_file)
            shutil.copy2(pov, staging / pov.name)
            env["POV_FILE"] = f"/workspace/{pov.name}"

        if custom_run_command:
            env["CUSTOM_RUN_CMD"] = custom_run_command

        # Copy patch
        if patch_file:
            pf = Path(patch_file)
            shutil.copy2(pf, staging / pf.name)
            env["PATCH_FILE"] = f"/workspace/{pf.name}"

        # Copy any extra files (e.g., Makefile, headers)
        if extra_files:
            for dest_name, host_path in extra_files.items():
                shutil.copy2(host_path, staging / dest_name)

        # Run the container
        logger.info("Starting ASAN sandbox container …")
        try:
            container = self._get_client().containers.run(
                image=self.IMAGE_TAG,
                volumes={str(staging): {"bind": "/workspace", "mode": "rw"}},
                environment=env,
                detach=True,
                mem_limit="512m",
                network_mode="none",       # full network isolation
            )

            result = container.wait(timeout=self.timeout)
            exit_code = result.get("StatusCode", -1)
            logs = container.logs().decode("utf-8", errors="replace")

            container.remove(force=True)

        except Exception as exc:
            logger.error("Container error: %s", exc)
            return OracleResult(
                verdict=Verdict.TIMEOUT if "timeout" in str(exc).lower() else Verdict.UNKNOWN,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                asan_report="",
            )

        # Classify the result
        asan_report = _extract_asan(logs)
        verdict = _classify(exit_code, logs, asan_report)

        return OracleResult(
            verdict=verdict,
            exit_code=exit_code,
            stdout=logs,
            stderr="",
            asan_report=asan_report,
        )

    # -- Project test strategy (Python/JS/Java/Go/Rust/Ruby) ---------------

    def _run_project_tests(
        self,
        project_root: str | Path | None,
        patch_file: str | Path | None,
        language_profile: LanguageProfile | None,
        custom_test_command: str | None = None,
    ) -> OracleResult:
        """Apply patch to a copy of the project and run its test suite."""
        if project_root is None:
            return OracleResult(
                verdict=Verdict.SKIPPED,
                exit_code=0,
                stdout="No project_root provided; cannot run project tests.",
                stderr="",
                asan_report="",
            )

        if language_profile is None:
            return OracleResult(
                verdict=Verdict.SKIPPED,
                exit_code=0,
                stdout="No language_profile provided; cannot run project tests.",
                stderr="",
                asan_report="",
            )

        image_tag = self._build_multilang_image(language_profile)
        project_root = Path(project_root).resolve()

        # Stage: copy the entire project tree
        staging = Path(tempfile.mkdtemp(prefix="findvuln_ml_"))
        try:
            staged_project = staging / "project"
            shutil.copytree(project_root, staged_project)

            env = {
                "LANG_ID": language_profile.codeql_language,
                "PATCH_FILE": "",
            }

            if patch_file:
                pf = Path(patch_file)
                shutil.copy2(pf, staging / pf.name)
                env["PATCH_FILE"] = f"/staging/{pf.name}"

            if custom_test_command:
                env["CUSTOM_TEST_CMD"] = custom_test_command

            logger.info(
                "Starting %s test container for %s …",
                language_profile.display_name,
                project_root.name,
            )

            try:
                container = self._get_client().containers.run(
                    image=image_tag,
                    volumes={
                        str(staged_project): {"bind": "/workspace", "mode": "rw"},
                        str(staging): {"bind": "/staging", "mode": "ro"},
                    },
                    environment=env,
                    detach=True,
                    mem_limit="1g",
                    network_mode="none",
                    working_dir="/workspace",
                )

                result = container.wait(timeout=self.timeout)
                exit_code = result.get("StatusCode", -1)
                logs = container.logs().decode("utf-8", errors="replace")
                container.remove(force=True)

            except Exception as exc:
                logger.error("Container error: %s", exc)
                return OracleResult(
                    verdict=Verdict.TIMEOUT if "timeout" in str(exc).lower() else Verdict.UNKNOWN,
                    exit_code=-1,
                    stdout="",
                    stderr=str(exc),
                    asan_report="",
                )

            # Classify
            if exit_code == 0:
                verdict = Verdict.PASS
            elif exit_code == 2 or "PATCH_APPLY_FAILED" in logs:
                verdict = Verdict.PATCH_ERROR
            else:
                verdict = Verdict.TEST_FAILURE

            return OracleResult(
                verdict=verdict,
                exit_code=exit_code,
                stdout=logs,
                stderr="",
                asan_report="",
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_asan(logs: str) -> str:
    """Pull out the AddressSanitizer block from the combined logs."""
    lines = logs.splitlines()
    asan_lines: list[str] = []
    in_asan = False
    for line in lines:
        if "AddressSanitizer" in line or "ERROR:" in line:
            in_asan = True
        if in_asan:
            asan_lines.append(line)
        if in_asan and line.strip() == "":
            # blank line after the report ends the block
            if len(asan_lines) > 3:
                break
    return "\n".join(asan_lines)


def _classify(exit_code: int, logs: str, asan_report: str) -> Verdict:
    if exit_code == 0:
        return Verdict.PASS
    if exit_code == 2 or "PATCH_APPLY_FAILED" in logs:
        return Verdict.PATCH_ERROR
    if exit_code == 3 or "COMPILE_FAILED" in logs:
        return Verdict.COMPILE_ERROR
    if asan_report:
        return Verdict.CRASH
    return Verdict.CRASH  # non-zero exit without ASAN still counts as crash
