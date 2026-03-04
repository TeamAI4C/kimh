/**
 * @name Inter-procedural context-sensitive taint flow
 * @description Tracks tainted data from get_tainted_input() through
 *              intermediate functions to dangerous_sink(), while
 *              distinguishing tainted from safe call contexts.
 * @kind path-problem
 * @id findvuln/interprocedural-flow
 * @problem.severity error
 * @tags security
 *       cpg-analysis
 *       interprocedural
 *       external/cwe/cwe-120
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

/**
 * Source: return value of get_tainted_input().
 */
class TaintedInputSource extends DataFlow::Node {
  TaintedInputSource() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("get_tainted_input") and
      this.asExpr() = fc
    )
  }
}

/**
 * Sink: arguments to dangerous_sink().
 */
class DangerousSinkArg extends DataFlow::Node {
  DangerousSinkArg() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("dangerous_sink") and
      this.asExpr() = fc.getAnArgument()
    )
  }
}

/**
 * Taint tracking: get_tainted_input() → dangerous_sink() argument.
 * CodeQL's built-in context sensitivity should ensure that
 * process(safe_data) does NOT produce a flow path.
 */
module InterProcConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof TaintedInputSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof DangerousSinkArg
  }
}

module InterProcFlow = TaintTracking::Global<InterProcConfig>;

import InterProcFlow::PathGraph

from InterProcFlow::PathNode source, InterProcFlow::PathNode sink
where InterProcFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted data from $@ flows to dangerous_sink via inter-procedural path.",
  source.getNode(), "taint source"
