/**
 * @name Alias pointer and struct field use-after-free
 * @description Detects UAF through pointer aliases and tracks
 *              specific struct field accesses on freed memory.
 * @kind problem
 * @id findvuln/alias-field-uaf
 * @problem.severity error
 * @tags security
 *       cpg-analysis
 *       alias-tracking
 *       external/cwe/cwe-416
 */

import cpp

/**
 * Free calls (standard free).
 */
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasGlobalName("free")
  }

  Variable getFreedVariable() {
    result = this.getArgument(0).(VariableAccess).getTarget()
  }
}

/**
 * Detect pointer alias assignments: `ptr2 = ptr1`.
 */
class AliasAssignment extends AssignExpr {
  Variable sourceVar;
  Variable aliasVar;

  AliasAssignment() {
    sourceVar = this.getRValue().(VariableAccess).getTarget() and
    aliasVar = this.getLValue().(VariableAccess).getTarget() and
    sourceVar.getType().getUnspecifiedType() instanceof PointerType
  }

  Variable getSourceVar() { result = sourceVar }
  Variable getAliasVar() { result = aliasVar }
}

/**
 * Access to a struct field via pointer dereference (e.g., ptr->field).
 */
class FieldAccessAfterFree extends PointerFieldAccess {
  Variable accessedVar;
  FreeCall freeCall;
  string fieldName;

  FieldAccessAfterFree() {
    accessedVar = this.getQualifier().(VariableAccess).getTarget() and
    fieldName = this.getTarget().getName() and
    (
      // Direct: free(ptr); ptr->field
      freeCall.getFreedVariable() = accessedVar
      or
      // Alias: ptr2 = ptr1; free(ptr1); ptr2->field
      exists(AliasAssignment aa |
        aa.getSourceVar() = freeCall.getFreedVariable() and
        aa.getAliasVar() = accessedVar
      )
    ) and
    freeCall.getASuccessor+() = this
  }

  string getFieldName() { result = fieldName }
}

from FieldAccessAfterFree access
select access,
  "Use-after-free: accessing field '" + access.getFieldName() +
  "' on freed memory via " +
  access.getQualifier().(VariableAccess).getTarget().getName() + "."
