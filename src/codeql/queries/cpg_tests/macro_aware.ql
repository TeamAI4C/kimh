/**
 * @name Macro-aware sanitizer detection (SAFE_FREE)
 * @description Detects use-after-free while recognizing that the
 *              SAFE_FREE macro (free + NULL assignment) sanitizes
 *              the pointer, preventing UAF on the sanitized path.
 * @kind path-problem
 * @id findvuln/macro-aware-uaf
 * @problem.severity error
 * @tags security
 *       cpg-analysis
 *       macro-sanitizer
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.Guards

// ---------------------------------------------------------------------------
// 1. Detect SAFE_FREE macro invocations
// ---------------------------------------------------------------------------

/**
 * A macro invocation of SAFE_FREE.
 * After expansion, the pointer is set to NULL.
 */
class SafeFreeMacro extends MacroInvocation {
  SafeFreeMacro() {
    this.getMacroName() = "SAFE_FREE"
  }
}

// ---------------------------------------------------------------------------
// 2. Standard alloc / free / post-free-use
// ---------------------------------------------------------------------------

class AllocCall extends FunctionCall {
  AllocCall() {
    this.getTarget().hasGlobalName(["malloc", "calloc", "realloc"])
  }
}

class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasGlobalName("free")
  }

  Expr getFreedArg() { result = this.getArgument(0) }
}

/**
 * A use after free, but NOT if the free was inside a SAFE_FREE macro
 * (since SAFE_FREE also NULLs the pointer).
 */
class PostFreeUse extends Expr {
  PostFreeUse() {
    exists(VariableAccess va |
      va = this and
      exists(FreeCall fc |
        fc.getFreedArg().(VariableAccess).getTarget() = va.getTarget() and
        fc.getASuccessor+() = va and
        // Exclude free calls inside SAFE_FREE macro expansions
        not fc.isInMacroExpansion()
      )
    )
  }
}

// ---------------------------------------------------------------------------
// 3. DataFlow configuration
// ---------------------------------------------------------------------------

module MacroAwareUafConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof AllocCall
  }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof PostFreeUse
  }
}

module MacroAwareUafFlow = DataFlow::Global<MacroAwareUafConfig>;

import MacroAwareUafFlow::PathGraph

from MacroAwareUafFlow::PathNode source, MacroAwareUafFlow::PathNode sink
where MacroAwareUafFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Use-after-free: $@ is freed (not via SAFE_FREE) and then used here.",
  source.getNode(), "allocation site"
