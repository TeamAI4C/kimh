#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Sandbox entrypoint — compile with ASAN, optionally apply a
# patch, then run the binary with a PoV input.
#
# Expected environment variables (set by the Python driver):
#   SRC_FILE      – path to the C source file inside /workspace
#   BINARY_NAME   – desired output binary name
#   POV_FILE      – path to PoV input file (stdin redirect)
#   PATCH_FILE    – (optional) path to a .diff to apply first
#   ASAN_FLAGS    – compiler sanitizer flags
#   COMPILER      – gcc or g++
#   CUSTOM_RUN_CMD – (optional) explicit runtime command for trigger testing
# ──────────────────────────────────────────────────────────────
set -euo pipefail

COMPILER="${COMPILER:-gcc}"
ASAN_FLAGS="${ASAN_FLAGS:--fsanitize=address -fno-omit-frame-pointer -g}"
SRC_FILE="${SRC_FILE:-/workspace/target.c}"
BINARY_NAME="${BINARY_NAME:-target}"
POV_FILE="${POV_FILE:-/workspace/pov_input.txt}"
PATCH_FILE="${PATCH_FILE:-}"
CUSTOM_RUN_CMD="${CUSTOM_RUN_CMD:-}"

echo "=== FindVuln Sandbox ==="
echo "Source : $SRC_FILE"
echo "Compiler: $COMPILER $ASAN_FLAGS"

# ── Step 1: Apply patch (if provided) ─────────────────────────
if [ -n "$PATCH_FILE" ] && [ -f "$PATCH_FILE" ]; then
    echo "--- Applying patch: $PATCH_FILE"
    # Use --directory to set the strip level correctly
    cd /workspace
    if ! patch -p1 < "$PATCH_FILE" 2>&1; then
        echo "PATCH_APPLY_FAILED"
        exit 2
    fi
    echo "--- Patch applied successfully."
fi

# ── Step 2: Compile ──────────────────────────────────────────
echo "--- Compiling $SRC_FILE"
COMPILE_CMD="$COMPILER $ASAN_FLAGS -o /workspace/$BINARY_NAME $SRC_FILE"
echo "    $COMPILE_CMD"

if ! eval "$COMPILE_CMD" 2>&1; then
    echo "COMPILE_FAILED"
    exit 3
fi
echo "--- Compilation succeeded."

# ── Step 3: Run with PoV input ───────────────────────────────
echo "--- Running /workspace/$BINARY_NAME with PoV input"
set +e   # don't exit on non-zero

if [ -n "$CUSTOM_RUN_CMD" ]; then
    echo "--- Running custom trigger command"
    echo "    $CUSTOM_RUN_CMD"
    bash -lc "$CUSTOM_RUN_CMD" 2>&1
elif [ -f "$POV_FILE" ]; then
    /workspace/"$BINARY_NAME" < "$POV_FILE" 2>&1
else
    /workspace/"$BINARY_NAME" 2>&1
fi

EXIT_CODE=$?
set -e

echo ""
echo "--- EXIT_CODE=$EXIT_CODE"
exit $EXIT_CODE
