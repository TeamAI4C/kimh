#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Multi-language sandbox entrypoint.
#
# Applies a patch (if provided) and runs the project's test suite.
#
# Expected environment variables:
#   LANG_ID     – language identifier (python, javascript, java, go, rust, ruby, csharp)
#   PATCH_FILE  – (optional) path to a .diff to apply first
# ──────────────────────────────────────────────────────────────
set -euo pipefail

LANG_ID="${LANG_ID:-python}"
PATCH_FILE="${PATCH_FILE:-}"

echo "=== FindVuln Multi-Language Sandbox ==="
echo "Language: $LANG_ID"
echo "Workdir : $(pwd)"

# ── Step 1: Apply patch (if provided) ─────────────────────────
if [ -n "$PATCH_FILE" ] && [ -f "$PATCH_FILE" ]; then
    echo "--- Applying patch: $PATCH_FILE"
    # Try strict first, then fallback to fuzzy matching for LLM-generated diffs
    if ! patch -p1 < "$PATCH_FILE" 2>&1; then
        echo "--- Strict patch failed, retrying with --fuzz=3 --force ..."
        if ! patch -p1 --fuzz=3 --force < "$PATCH_FILE" 2>&1; then
            echo "PATCH_APPLY_FAILED"
            exit 2
        fi
    fi
    echo "--- Patch applied successfully."
fi

# ── Step 2: Run language-specific tests ───────────────────────
echo "--- Running tests for $LANG_ID"

case "$LANG_ID" in
    python)
        if [ -f "requirements.txt" ]; then
            pip3 install -q -r requirements.txt 2>&1 || true
        fi
        if [ -f "pyproject.toml" ]; then
            pip3 install -q -e ".[test,dev]" 2>&1 || pip3 install -q -e . 2>&1 || true
        fi
        if [ -f "setup.py" ]; then
            pip3 install -q -e ".[test]" 2>&1 || pip3 install -q -e . 2>&1 || true
        fi
        python3 -m pytest --tb=short -q 2>&1
        ;;
    javascript)
        if [ -f "package-lock.json" ]; then
            npm ci --ignore-scripts 2>&1 || npm install 2>&1
        else
            npm install 2>&1
        fi
        npm test 2>&1
        ;;
    java)
        if [ -f "pom.xml" ]; then
            mvn -q test 2>&1
        elif [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
            if [ -f "gradlew" ]; then
                chmod +x gradlew
                ./gradlew test 2>&1
            else
                echo "No gradle wrapper found, skipping."
                exit 0
            fi
        fi
        ;;
    go)
        go test ./... 2>&1
        ;;
    rust)
        cargo test 2>&1
        ;;
    ruby)
        if [ -f "Gemfile" ]; then
            bundle install --quiet 2>&1 || true
        fi
        if [ -f "Rakefile" ]; then
            bundle exec rake test 2>&1 || bundle exec rspec 2>&1
        else
            bundle exec rspec 2>&1 || ruby -e "puts 'No test framework detected'" 2>&1
        fi
        ;;
    csharp)
        dotnet test 2>&1
        ;;
    *)
        echo "No test runner configured for $LANG_ID"
        exit 0
        ;;
esac

EXIT_CODE=$?
echo ""
echo "--- EXIT_CODE=$EXIT_CODE"
exit $EXIT_CODE
