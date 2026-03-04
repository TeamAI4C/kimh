/**
 * @name Function pointer indirect call resolution
 * @description Tracks function pointers from assignment to indirect call
 *              site to determine which target function may be invoked.
 * @kind path-problem
 * @id findvuln/fn-pointer-resolve
 * @problem.severity warning
 * @tags security
 *       cpg-analysis
 *       function-pointer
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Source: taking the address of a function (FunctionAccess).
 * For example: `void (*fp)(char*) = dangerous_func;`
 */
class FuncAddrSource extends DataFlow::Node {
  FuncAddrSource() {
    exists(FunctionAccess fa |
      this.asExpr() = fa
    )
  }

  string getTargetName() {
    result = this.asExpr().(FunctionAccess).getTarget().getName()
  }
}

/**
 * Sink: the callee expression of an indirect call (ExprCall).
 * For example: `fp(tainted);` — the `fp` is the sink.
 */
class IndirectCallSink extends DataFlow::Node {
  IndirectCallSink() {
    exists(ExprCall ec |
      this.asExpr() = ec.getExpr()
    )
  }
}

/**
 * DataFlow configuration: function address → indirect call callee.
 */
module FnPtrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FuncAddrSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof IndirectCallSink
  }
}

module FnPtrFlow = DataFlow::Global<FnPtrConfig>;

import FnPtrFlow::PathGraph

from FnPtrFlow::PathNode source, FnPtrFlow::PathNode sink
where FnPtrFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Indirect call may invoke $@.",
  source.getNode(),
  source.getNode().asExpr().(FunctionAccess).getTarget().getName()
