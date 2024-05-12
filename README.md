# Gecko Skeleton (non-working POC)    

When scaling up in both offensive and defensive cyber tools,  
the need arrises to create generic abstractions in order to create specific configuration profiles for the tools.

For offensive cyber one might need to be able to overwrite a specific member in a struct, so they need to know the offset of the struct beforehand.
For defensive cyber one might want to analyse a memory dump, but they don't have access to the sourcecode/debug symbols of the system's code, so they don't have information about compiled structures.  

For example we want to run a [Volatility](https://github.com/volatilityfoundation/volatility) plugin on a memory dump, but we weren't given any data other than the dump.   
Can we use information/code existing in the dump to guess the specifics for the configuration profile we need?    

The Volatility plugin  `linux_pslist` needs several members for the `task_struct` structure (`comm`, `pid`, `next`, ...).  
If we find a kernal function which does something like
```c
printk("Process %s (%d) crashed.\n", task->comm, task->pid);
```
we should be able to analyse it and reconstruct needed offsets of different members in the `task_struct` structure   
(by finding the string -> finding the call -> finding the 2nd and 3rd arguments to the call).   

## Static analysis framework built around angr &amp; IDA

The idea is to use a symbolic execution framework combined with a static analysis framework  
in order to create generic heuristical signatures for compiled code,  
based on our expectations of how the code behaves.  

Using these signatures we can then reconstruct structures and find useful primitives   
for any compiled codebase which adheres with the signature,  
removing the need of accessing the source code or debug symbols for the code we're interested in.  

## How it works

The angr symbolic execution framework enables us to lift compiled code into an intermediate representation  
so an analysis is written somewhat generically and not for a specific instruction set,  
as well as symbolically execute specific parts of code while analysing the memory operations and identifying behaviors.

Combining this with a strong static analysis framework like IDA enables us to find "anchors" (specific strings, integers, function calls, ...)    
and create generic heuristical signatures on the intermediate representation.  

This is useful to reconstruct structures and find addresses/offsets in compiled code.  
Can be used to create configuration profiles for exploits or memory forensics.    

