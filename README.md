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
Tracking the vulnerability allows us to see where the flow is stopping. My guess is that getters/setters methods will often overwrite the tainted data and leaving it unconstrained could also return a very large number of results. I found out about this when a poorly written query consumed all my RAM :). We need to limit the number of sources.

## Step 1.6: Additional taint steps

## Step 1.7: Adding constructors to taint tracking flows

## Step 1.8: Finish line
![](img/1.8.PNG)

# Step 2: Another issue
![](img/2.PNG)

# Step 3: Errors and exceptions
![](img/3.PNG)

# Step 4: Exploit and remediation
## Step 4.1:
## Step 4.2:


