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


