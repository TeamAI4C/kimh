/**
 * @name Buffer overflow with sanitizer barrier
 * @description Detects buffer overflows from user input while
 *              recognizing bounds checks as barriers that prune
 *              safe paths.
 * @kind path-problem
 * @id findvuln/sanitizer-barrier-bof
 * @problem.severity error
 * @tags security
 *       cpg-analysis
 *       sanitizer-barrier
 *       external/cwe/cwe-120
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards

/**
 * Source: return value of read_user_input().
 */
class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("read_user_input") and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

/**
 * Sink: destination argument of strcpy.
 */
class StrcpySink extends DataFlow::Node {
  StrcpySink() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalName("strcpy") and
      this.asExpr() = fc.getArgument(1)
    )
  }
}

/**
 * Barrier guard: a bounds check comparing length against a constant.
 * For example: `if (len >= MAX_BUF) return;`
 *
 * After this guard evaluates to false (i.e., len < MAX_BUF),
 * the taint is considered sanitized.
 */
class BoundsCheckGuard extends DataFlow::Node {
  BoundsCheckGuard() {
    exists(GuardCondition gc, Variable lenVar |
      gc.ensuresLt(lenVar.getAnAccess(), any(Expr e), _, this.asExpr().getBasicBlock(), true)
    )
  }
}

/**
 * Taint tracking with barrier: user input → strcpy, pruned by bounds check.
 */
module BoundedBofConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof StrcpySink
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof BoundsCheckGuard
  }
}

module BoundedBofFlow = TaintTracking::Global<BoundedBofConfig>;

import BoundedBofFlow::PathGraph

from BoundedBofFlow::PathNode source, BoundedBofFlow::PathNode sink
where BoundedBofFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Buffer overflow: user input from $@ flows to strcpy without adequate bounds check.",
  source.getNode(), "user input"
