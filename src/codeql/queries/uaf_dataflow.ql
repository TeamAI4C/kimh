/**
 * @name Use-After-Free dataflow chain
 * @description Tracks the lifecycle of a heap pointer through
 *              allocation → free → use, producing a sequential
 *              path suitable for LLM consumption.
 * @kind path-problem
 * @id findvuln/uaf-dataflow
 * @problem.severity error
 * @tags security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards
import DataFlow::PathGraph

// ---------------------------------------------------------------------------
// 1.  Identify Sources  (malloc / calloc / realloc)
// ---------------------------------------------------------------------------
class AllocCall extends FunctionCall {
  AllocCall() {
    this.getTarget().hasGlobalName(["malloc", "calloc", "realloc"])
  }
}

// ---------------------------------------------------------------------------
// 2.  Identify Free-sites
// ---------------------------------------------------------------------------
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasGlobalName("free")
  }

  Expr getFreedArg() { result = this.getArgument(0) }
}

// ---------------------------------------------------------------------------
// 3.  Identify post-free Uses  (any read/deref after free)
// ---------------------------------------------------------------------------
class PostFreeUse extends Expr {
  PostFreeUse() {
    exists(VariableAccess va |
      va = this and
      exists(FreeCall fc |
        fc.getFreedArg().(VariableAccess).getTarget() = va.getTarget() and
        fc.getASuccessor+() = va
      )
    )
  }
}

// ---------------------------------------------------------------------------
// 4.  DataFlow configuration: alloc → free → use
// ---------------------------------------------------------------------------
class UafConfig extends DataFlow::Configuration {
  UafConfig() { this = "UafConfig" }

  override predicate isSource(DataFlow::Node src) {
    src.asExpr() instanceof AllocCall
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof PostFreeUse
  }
}

// ---------------------------------------------------------------------------
// 5.  Query – emit path nodes
// ---------------------------------------------------------------------------
from UafConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Use-after-free: memory allocated at $@ is freed and then used here.",
  source.getNode(), "allocation site"
