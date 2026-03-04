/**
 * @name Use-after-free via custom allocator
 * @description Detects use-after-free when custom allocator wrappers
 *              (my_alloc / my_free) are used instead of malloc / free.
 * @kind path-problem
 * @id findvuln/custom-alloc-uaf
 * @problem.severity error
 * @tags security
 *       cpg-analysis
 *       custom-allocator
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Calls to the custom allocator wrapper (my_alloc).
 */
class MyAllocCall extends FunctionCall {
  MyAllocCall() {
    this.getTarget().hasName("my_alloc")
  }
}

/**
 * Calls to the custom deallocator wrapper (my_free).
 */
class MyFreeCall extends FunctionCall {
  MyFreeCall() {
    this.getTarget().hasName("my_free")
  }

  Expr getFreedArg() { result = this.getArgument(0) }
}

/**
 * A variable access that occurs after a my_free call on the same variable.
 */
class PostMyFreeUse extends Expr {
  PostMyFreeUse() {
    exists(VariableAccess va |
      va = this and
      exists(MyFreeCall fc |
        fc.getFreedArg().(VariableAccess).getTarget() = va.getTarget() and
        fc.getASuccessor+() = va
      )
    )
  }
}

/**
 * DataFlow: my_alloc() → post-my_free use.
 */
module CustomAllocUafConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof MyAllocCall
  }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof PostMyFreeUse
  }
}

module CustomAllocUafFlow = DataFlow::Global<CustomAllocUafConfig>;

import CustomAllocUafFlow::PathGraph

from CustomAllocUafFlow::PathNode source, CustomAllocUafFlow::PathNode sink
where CustomAllocUafFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Use-after-free: memory from custom allocator $@ is freed via my_free and then used here.",
  source.getNode(), "my_alloc call"
