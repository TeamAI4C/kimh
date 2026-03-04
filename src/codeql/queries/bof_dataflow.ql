/**
 * @name Buffer Overflow dataflow chain
 * @description Tracks unbounded copies into fixed-size buffers.
 * @kind path-problem
 * @id findvuln/bof-dataflow
 * @problem.severity error
 * @tags security
 *       external/cwe/cwe-120
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import DataFlow::PathGraph

// ---------------------------------------------------------------------------
// Source: user-controlled data entering the program (parameters, reads)
// ---------------------------------------------------------------------------
class TaintedParam extends DataFlow::Node {
  TaintedParam() {
    exists(Parameter p | this.asParameter() = p)
  }
}

// ---------------------------------------------------------------------------
// Sink: dangerous copy functions (strcpy, strcat, sprintf, gets)
// ---------------------------------------------------------------------------
class UnsafeCopyCall extends FunctionCall {
  UnsafeCopyCall() {
    this.getTarget().hasGlobalName(["strcpy", "strcat", "sprintf", "gets"])
  }

  Expr getDestArg() { result = this.getArgument(0) }
  Expr getSrcArg()  {
    if this.getTarget().hasGlobalName("gets")
    then result = this.getArgument(0)
    else result = this.getArgument(1)
  }
}

// ---------------------------------------------------------------------------
// DataFlow configuration
// ---------------------------------------------------------------------------
class BofConfig extends DataFlow::Configuration {
  BofConfig() { this = "BofConfig" }

  override predicate isSource(DataFlow::Node src) {
    src instanceof TaintedParam
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(UnsafeCopyCall call | call.getSrcArg() = sink.asExpr())
  }
}

from BofConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Buffer overflow: tainted data from $@ flows into an unsafe copy here.",
  source.getNode(), "tainted source"
