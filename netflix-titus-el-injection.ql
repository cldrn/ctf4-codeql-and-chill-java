/** @kind path-problem */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/*
* ConstraintValidatorClass (Class)
* Holds classes implementing javax.validation.ConstraintValidator<>'s
*/
class ConstraintValidatorClass extends Class {
    ConstraintValidatorClass() {
        this.getASupertype().getASupertype+().hasQualifiedName("javax.validation", "ConstraintValidator<>")
    }
}

/*
* ConstraintValidatorIsValid (Method)
* Holds method isValid implemented in the ConstraintValidator interface
*/
class ConstraintValidatorIsValid extends Method {
    ConstraintValidatorIsValid() {
        this.getDeclaringType() instanceof ConstraintValidatorClass //javax.validation.ConstraintValidator<>'s
        and this.hasName("isValid") //Only methods with name 'isValid'
        and not(this.isPrivate()) //Only methods in the ConstraintValidator interface (We can also look for the @override annotation - and this.hasAnnotation())
    }
}

/*
* ConstraintValidatorContextClass (Class)
*/
class ConstraintValidatorContextClass extends Class {
    ConstraintValidatorContextClass() {
        this.hasQualifiedName("javax.validation", "ConstraintValidatorContext")
    }
}

/*
* isBuildConstraintViolationWithTemplate
* Returns expression holding the first argument of method calls to 'buildConstraintViolationWithTemplate'
*/
predicate isBuildConstraintViolationWithTemplate(Expr arg) {
    exists(MethodAccess buildCallAccess |
        buildCallAccess.getMethod().getName() = "buildConstraintViolationWithTemplate"
        and arg = buildCallAccess.getArgument(0)
    )
}

/*
* The names of funtions that we want to allow taint tracking flow
*/
class FlowConstraints extends Method {
    FlowConstraints() {
        this.hasName("getSoftConstraints")
        or this.hasName("getHardConstraints")
        or this.hasName("keySet") 
        or this.hasName("stream")
        or this.hasName("map")
        or this.hasName("collect")
    }
}

/*
* HashSet constructor classes
*/
class TypeHashtable extends RefType {
TypeHashtable() { 
    hasQualifiedName("java.util", "HashSet")
    or hasQualifiedName("java.util", "HashSet<>")
    or hasQualifiedName("java.util", "HashSet<String>") 
    }
}

/*
* Holds for Netflix Titus flow constraints
*/
predicate expressionCompileStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma, Method m | ma.getMethod() = m |
        m instanceof FlowConstraints
        and ma = node2.asExpr()
        and ma.getQualifier() = node1.asExpr()
    )
}

/*
* Allows the flow through hashSet constructors
*/
predicate hashSetMethodStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(ConstructorCall cc | cc.getConstructedType() instanceof TypeHashtable |
        node1.asExpr() = cc.getAnArgument()
        and (node2.asExpr() = cc or node2.asExpr() = cc.getQualifier())
    )
}

/*
* Holds for Exception and Throwable argument names
*/
private predicate catchTypeNames(string typeName) {
    typeName = "Throwable" or typeName = "Exception"
}

/*
* Holds for calls in catch statements that match certain function names
*/
predicate catchStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Method m, MethodAccess ma, CatchClause cc, LocalVariableDeclExpr v, TryStmt t, string typeName |
        catchTypeNames(typeName) 
        and t.getACatchClause() = cc  
        and cc.getVariable() = v
        and v.getType().(RefType).hasQualifiedName("java.lang", typeName)
        and exists(v.getAnAccess()) 
        and ma.getMethod() = m
        and ma.getAnArgument().getType() = cc.getVariable().getType() 
        and m.getName() = "buildConstraintViolationWithTemplate"
        and node2.asExpr() = ma
        and node1.asExpr() = ma.getQualifier()
    )
}

/*
* TitusTTConf - TaintTracking Configuration for EL injection in Titus
* Source: ConstraintValidator.isValid(*,)
* Sink: ConstraintValidatorContext.buildConstraintViolationWithTemplate(*,)
*/
class TitusTTConf extends TaintTracking::Configuration {
    TitusTTConf() { this = "TitusTTConf" }

    override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        expressionCompileStep(node1, node2)
        or hashSetMethodStep(node1, node2)
        or catchStep(node1, node2)
    }
    override predicate isSource(DataFlow::Node source) { 
        exists( ConstraintValidatorIsValid c |
        //I was aware of the class RemoteFlowSource but the following line didn't work as expected
            //source instanceof RemoteFlowSource and
            source.asParameter() = c.getParameter(0) 
        )
    }

    override predicate isSink(DataFlow::Node sink) { 
        exists( Expr arg |
            isBuildConstraintViolationWithTemplate(arg)
            and sink.asExpr() = arg 
        )

    }
}

from TitusTTConf cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"