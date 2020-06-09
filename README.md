# ctf4-codeql-and-chill-java
GitHub Security Lab CTF 4: CodeQL and Chill - The Java Edition

## TaintTracking Configuration for Netflix Titus
I've been wanting to look into the power of TaintTracking in CodeQL for some time and this CTF is perfect for learning and practicing against a real life target. The challenge takes you from setting up flow paths to fully customizing them when tracking the vulnerabilities and puts the cherry on top with an interesting Java EL injection.

Let's CodeQL and chill!

## Step 1.1: Setting up our source
We are setting the source to be the first parameter of `ConstraintValidator.isValid()`. We start by modeling a QL class to filter Java classes that implement javax.validation.ConstraintValidator:

```java
/*
* ConstraintValidatorClass (Class)
* Holds classes implementing javax.validation.ConstraintValidator<>'s
*/
class ConstraintValidatorClass extends Class {
    ConstraintValidatorClass() {
        this.getASupertype().getASupertype+().hasQualifiedName("javax.validation", "ConstraintValidator<>")
    }
}
```

Now we need a class to reference the `isValid` method that meets the following criteria:
* Must be in a class that implements `javax.validation.ConstraintValidator<>`
* Only methods in the ConstraintValidator interface
* Has the name `isValid`

```java
/*
* ConstraintValidatorIsValid (Method)
* Holds method isValid implemented in the ConstraintValidator interface
*/
class ConstraintValidatorIsValid extends Method {
    ConstraintValidatorIsValid() {
        this.getDeclaringType() instanceof ConstraintValidatorClass //javax.validation.ConstraintValidator<>'s
        and this.hasName("isValid") //Only methods with name 'isValid'
        and not(this.isPrivate()) //Only methods in the ConstraintValidator interface 
        //and this.hasAnnotation() //We can also look for the @override annotation)
    }
}
```
After modeling our method in QL, we use that class to set the first parameter as the source:
```java
    override predicate isSource(DataFlow::Node source) { 
        exists( ConstraintValidatorIsValid c |
        //I was aware of the class RemoteFlowSource but the following line didn't work as expected
            //source instanceof RemoteFlowSource and
            source.asParameter() = c.getParameter(0) 
        ) 
    }
```
After this, we get our 6 results as expected!

![](img/1.1.PNG)

## Step 1.2: Setting up our sinks
It is time to set up our sinks as the first argument of method calls to `buildConstraintViolationWithTemplate`:
```java
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
```
Now we can refer to this expression inside our TaintTracking configuration as follows:
```java
    override predicate isSink(DataFlow::Node sink) { 
        exists( Expr arg |
            isBuildConstraintViolationWithTemplate(arg)
            and sink.asExpr() = arg 
        ) 
    }
```
And now we can clearly identify our five sinks.

![](img/1.2.PNG)

## Step 1.3: Our taint tracking configuration
Let's put together our first attempt at taint tracking:
```
/*
* TitusTTConf - TaintTracking Configuration for EL injection in Titus
* Source: ConstraintValidator.isValid(*,)
* Sink: ConstraintValidatorContext.buildConstraintViolationWithTemplate(*,)
*/
class TitusTTConf extends TaintTracking::Configuration {
    TitusTTConf() { this = "TitusTTConf" }

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

```
## Step 1.4: Partial flowing
For this step, we need to use partial flows to detect where the flows stops being tracked. This is very useful for debugging as flows don't propagate through getters/setters and other methods.

To constrain all the possible sources, we could filter by file name:
```
source.getNode().getEnclosingCallable().getFile().toString() = "SchedulingConstraintValidator"
```
Or maybe by the type of parameter:
```
source.getNode().getEnclosingCallable().getParameterType(0) instanceof ContainerClass 
```
And there are many other possibilities available. We will use `DataFlow::PartialPathNode` for this part. Putting everything together we have the following query:
```
/*
* Holds for classes named Container
*/
class ContainerClass extends Class {
    ContainerClass() {
        this.getName() = "Container"
    }
}

class TitusTTConfig extends TaintTracking::Configuration {
    TitusTTConfig() { this = "TitusTTConfig" }

    override predicate isSource(DataFlow::Node source) { 
        exists( ConstraintValidatorIsValid c |
            source.asParameter() = c.getParameter(0)
        )
    }

    override predicate isSink(DataFlow::Node sink) { 
        exists( Expr arg |
            isBuildConstraintViolationWithTemplate(arg) and
            sink.asExpr() = arg 
        ) 
    }    
    override int explorationLimit() { result =  10} 
}

from TitusTTConfig cfg, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink, int dist
where 
cfg.hasPartialFlow(source, sink, dist)
//and source.getNode().getEnclosingCallable().getFile().toString() = "SchedulingConstraintValidator" //By filename
and source.getNode().getEnclosingCallable().getParameterType(0) instanceof ContainerClass //By type

select sink, source, sink, "Partial flow from unsanitized user data:"
```
Now, we can focus on specific flows that we are tracking. The arguments of type Container look interesting:

![](img/1.4.PNG)

## Step 1.5: Missing taint steps
Tracking the vulnerability allow us to see where the flow is stopping. My guess is that getters/setters methods will often overwrite the tainted data and leaving it unconstrained could also return a very large number of results. I found out about this when a poorly written query consumed all my RAM :). We need to limit the number of sources.

## Step 1.6: Additional taint steps
Now we define an additional taint tracking step that defines a new flow through these functions to be placed right before the HashSet constructor call. We define a class and a predicate to be called from the step call:

```
class FlowConstraints extends Method {
    FlowConstraints() {
        this.hasName("getSoftConstraints")
        or this.hasName("getHardConstraints")
        or this.hasName("keySet")
    }
}
predicate expressionCompileStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma, Method m | ma.getMethod() = m |
        m instanceof FlowConstraints and
        ma = node2.asExpr() and
        ma.getQualifier() = node1.asExpr()
    )
}
```

We extend the TaintTracking::AdditionalTaintStep class as follows:

```
class NetflixTitusSteps extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        expressionCompileStep(node1, node2) 
    }
}
```
## Step 1.7: Adding taint steps through constructors
To add the step through the constructor of HashSet we need to define another predicate:

```
/*
* HashSet constructor classes
*/
class TypeHashtable extends RefType {
TypeHashtable() { 
    hasQualifiedName("java.util", "HashSet") or
    hasQualifiedName("java.util", "HashSet<>") or
    hasQualifiedName("java.util", "HashSet<String>") 
    }
}

predicate hashSetMethodStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(ConstructorCall cc | cc.getConstructedType() instanceof TypeHashtable |
        node1.asExpr() = cc.getAnArgument() and
        (node2.asExpr() = cc or node2.asExpr() = cc.getQualifier())
    )
}
```
And update our step call:
```
class NetflixTitusSteps extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
        expressionCompileStep(node1, node2) or
        hashSetMethodStep(node1, node2)
  }
}
```

## Step 1.8: Finish line
After adding the missing taint steps, we can run the query again and we get our first result.

![](img/1.8.PNG)

# Step 2: Another issue
To avoid code repetition, I will update our existing class `FlowConstraints`. After debuging the flow track in `SchedulingConstraintSetValidator` we can update our previously defined class with the missing methods.
```
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
```
Running the query again will return us the result we were missing!

![](img/2.PNG)

# Step 3: Errors and exceptions
For step 3, we need to update our query to include the case where the sink is called from within a catch statement:
```java
try {
    parse(tainted);
} catch (Exception e) {
    sink(e.getMessage())
}
```

For this step, we are  interested on the method calls done inside catch statements that use the Exception/Throwable argument in the catch clause. Since this specific use case is not in the source code, I wrote a standalone query that I can turn into a predicate for the step() call when ready. The following query detects method access where the variable passed to the `catch` statement is accessed by a function.

```
import java
 
private predicate catchTypeNames(string typeName) {
  typeName = "Throwable" or typeName = "Exception"
}

from Method m, MethodAccess ma, CatchClause cc, LocalVariableDeclExpr v, TryStmt t, string typeName
where
  catchTypeNames(typeName)
  and t.getACatchClause() = cc
  and cc.getVariable() = v
  and v.getType().(RefType).hasQualifiedName("java.lang", typeName)
  and exists(v.getAnAccess())
  and ma.getMethod() = m
  and ma.getAnArgument().getType() = cc.getVariable().getType()
select cc.getVariable().getType(), ma
```

![](img/3-1.PNG)

Now that I know that I'm selecting what I'm looking for, I can rewrite the query as a predicate and add some simple heuristic to detect calls to our desired sinks. One way to achieve this is filtering by name, let's look for `buildConstraintViolationWithTemplate` with the following query:
```
private predicate catchTypeNames(string typeName) {
  typeName = "Throwable" or typeName = "Exception"
}
predicate catchStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Method m, MethodAccess ma, CatchClause cc, LocalVariableDeclExpr v, TryStmt t, string typeName, Expr arg|
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
```
Since the vulnerable pattern is not in our code base, we can test our new step() by changing to the name of the function(s) for some other existing call such as `failed(...)`.

![](img/3-2.PNG)

At the end, our final predicate for `isAdditionalTaintStep` is:
```
   override predicate isAdditionalTaintStep(DataFlow::Node node1,
                                           DataFlow::Node node2) {

        expressionCompilerCompileStep(node1, node2)
        or hashSetMethodStep(node1, node2)
        or catchStep(node1, node2)
    }
```
Excellent, we have located the two vulnerable injection points and our query is robust enough to detect some edge cases. It is time to move to the exploitation part.

# Step 4: Exploit and remediation
## Step 4.1:
### Running Netflix Titus
Running the vulnerable version of Netflix Titus was easy as they provide Docker images. 
## Step 4.2:


