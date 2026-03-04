"""
Language detection and profile management for multi-language analysis.

Detects the primary language of a project by examining marker files,
and provides language-specific configuration profiles for the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class LanguageProfile:
    """Language-specific configuration for the analysis pipeline."""
    codeql_language: str        # CodeQL language identifier (e.g., "cpp", "python")
    display_name: str           # Human-readable name (e.g., "C/C++", "Python")
    code_fence: str             # Markdown code fence language (e.g., "c", "python")
    query_pack: str             # CodeQL query pack for security-extended suite
    build_mode: str             # "none" | "autobuild" | "manual"
    sandbox_strategy: str       # "asan" | "test_runner" | "build_and_test" | "skip"
    file_extensions: tuple[str, ...] = ()  # Primary source extensions


# ---------------------------------------------------------------------------
# Language profiles
# ---------------------------------------------------------------------------

PROFILES: dict[str, LanguageProfile] = {
    "cpp": LanguageProfile(
        codeql_language="cpp",
        display_name="C/C++",
        code_fence="c",
        query_pack="codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
        build_mode="manual",
        sandbox_strategy="asan",
        file_extensions=(".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"),
    ),
    "python": LanguageProfile(
        codeql_language="python",
        display_name="Python",
        code_fence="python",
        query_pack="codeql/python-queries:codeql-suites/python-security-extended.qls",
        build_mode="none",
        sandbox_strategy="test_runner",
        file_extensions=(".py",),
    ),
    "javascript": LanguageProfile(
        codeql_language="javascript",
        display_name="JavaScript/TypeScript",
        code_fence="javascript",
        query_pack="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        build_mode="none",
        sandbox_strategy="test_runner",
        file_extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    "java": LanguageProfile(
        codeql_language="java",
        display_name="Java/Kotlin",
        code_fence="java",
        query_pack="codeql/java-queries:codeql-suites/java-security-extended.qls",
        build_mode="autobuild",
        sandbox_strategy="build_and_test",
        file_extensions=(".java", ".kt"),
    ),
    "go": LanguageProfile(
        codeql_language="go",
        display_name="Go",
        code_fence="go",
        query_pack="codeql/go-queries:codeql-suites/go-security-extended.qls",
        build_mode="autobuild",
        sandbox_strategy="build_and_test",
        file_extensions=(".go",),
    ),
    "rust": LanguageProfile(
        codeql_language="rust",
        display_name="Rust",
        code_fence="rust",
        query_pack="codeql/rust-queries:codeql-suites/rust-security-extended.qls",
        build_mode="autobuild",
        sandbox_strategy="build_and_test",
        file_extensions=(".rs",),
    ),
    "ruby": LanguageProfile(
        codeql_language="ruby",
        display_name="Ruby",
        code_fence="ruby",
        query_pack="codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
        build_mode="none",
        sandbox_strategy="test_runner",
        file_extensions=(".rb",),
    ),
    "csharp": LanguageProfile(
        codeql_language="csharp",
        display_name="C#",
        code_fence="csharp",
        query_pack="codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
        build_mode="autobuild",
        sandbox_strategy="build_and_test",
        file_extensions=(".cs",),
    ),
    "swift": LanguageProfile(
        codeql_language="swift",
        display_name="Swift",
        code_fence="swift",
        query_pack="codeql/swift-queries:codeql-suites/swift-security-extended.qls",
        build_mode="autobuild",
        sandbox_strategy="build_and_test",
        file_extensions=(".swift",),
    ),
}

# Aliases → canonical key
_ALIASES: dict[str, str] = {
    "c": "cpp",
    "c++": "cpp",
    "cc": "cpp",
    "py": "python",
    "python3": "python",
    "js": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "javascript-typescript": "javascript",
    "jsx": "javascript",
    "tsx": "javascript",
    "java-kotlin": "java",
    "kotlin": "java",
    "kt": "java",
    "golang": "go",
    "rb": "ruby",
    "cs": "csharp",
    "c#": "csharp",
    "dotnet": "csharp",
}


def get_profile(language: str) -> LanguageProfile:
    """Look up a language profile by name or alias.

    Raises ValueError if the language is not recognized.
    """
    key = language.lower().strip()
    key = _ALIASES.get(key, key)
    if key not in PROFILES:
        supported = sorted(set(list(PROFILES.keys()) + list(_ALIASES.keys())))
        raise ValueError(
            f"Unsupported language: {language!r}. "
            f"Supported: {', '.join(supported)}"
        )
    return PROFILES[key]


# ---------------------------------------------------------------------------
# Marker-file → language mapping (order matters: first match wins)
# ---------------------------------------------------------------------------

_MARKERS: list[tuple[str, str]] = [
    # Go
    ("go.mod", "go"),
    ("go.sum", "go"),
    # Rust
    ("Cargo.toml", "rust"),
    # JavaScript / TypeScript
    ("package.json", "javascript"),
    ("tsconfig.json", "javascript"),
    # Python
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("setup.cfg", "python"),
    ("Pipfile", "python"),
    ("requirements.txt", "python"),
    # Java / Kotlin
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "java"),
    # Ruby
    ("Gemfile", "ruby"),
    # C#
    ("*.csproj", "csharp"),
    ("*.sln", "csharp"),
    # Swift
    ("Package.swift", "swift"),
    # C/C++ (last — many projects have a Makefile alongside another language)
    ("CMakeLists.txt", "cpp"),
    ("Makefile", "cpp"),
    ("configure.ac", "cpp"),
    ("meson.build", "cpp"),
]


def detect_language(project_root: str | Path) -> LanguageProfile:
    """Auto-detect the primary language of a project from its root directory.

    Scans for well-known marker files and returns the first matching profile.
    Raises ``ValueError`` if no markers are found.
    """
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError(f"Project root is not a directory: {root}")

    for marker, lang_key in _MARKERS:
        if "*" in marker:
            # Glob pattern (e.g., "*.csproj")
            if list(root.glob(marker)):
                return PROFILES[lang_key]
        else:
            if (root / marker).exists():
                return PROFILES[lang_key]

    raise ValueError(
        f"Could not detect project language in {root}. "
        "No recognized marker files found. Use --language to specify manually."
    )


def detect_or_resolve(
    project_root: str | Path,
    language: str = "auto",
) -> LanguageProfile:
    """Detect language automatically or resolve an explicit language name.

    This is the main entry point used by other pipeline components.
    """
    if language == "auto":
        return detect_language(project_root)
    return get_profile(language)
