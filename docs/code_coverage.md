# How does shaman help you with code coverage?

## Existing Solutions

- What are the existing tools for code coverage?
    - The mode popular option you have is your compiler. By enabling certain flags you can have binary compiled with additional code injected in the binary program which will create a very  covereage data in a file which can be later used to generate a beautiful looking code covereage report which highlight the code lines.
        - Pros
            - you get very accurate code coverage with each light highlighted with number of time the code was executed.
            - This option is very easy to follow and get the results.
        - Cons
            - This type of instrumentation will slowdown the program execution drastically which can become of problem in situation where performance of the real program might affect is functionality. 
                - For example imaging doing this for a game application where 60 fps can is a very critical information. 
                - It can also become challenge in other situation as well like embedded systems.
            - One solution to above problem is that once we have collected execution trace for a particular code we can restore the original code but this is not possible compile-time instrumentation settings.
            - You cannot do selective instrumentation, meaning you are only interested in collecting coverage for paritcular module, function or class. Doing this can restored some of the performance of the program lost due to coverage instrumentation.
            - You only have one option to dump the coverage which is file, this can drastically slowdown the overall activity of coverage reporting. Imagine if you can collect the covereage data in a shared memory buffer or stream it over network socket and collect it on different device.
            - You cannot use this if you don't have access to source code and if you don't know how to recompile the program with coverage option.
            - You can only collect execution trace, you cannot configure the tool to collect any other type of data. Like function parameters, Register values or stack trace of function.
            - You cannot use this technique in situation where target doesn't have standard file systems like micro-controllers.
    - There are some there tools which comes integerated
    - MPLAB Code Coverage by Micro Chip for Micro-controller
- https://ldra.com/capabilities/code-coverage-analysis/#CA14
## Dynamic Coverage Reporting

This approach dynamically modifies the program to insert code which will report the execution trace. This method provides more flexibility since you can dynamically add/remove instrumentation, this setting give you the ability to add business logic to the tracing. Besides this you have many advantages like
1. In fuzzing use cases you can dynamically add/remove instrumentation if get more performance like 
1. You can share the covereage data via different channels like shared memory(like AFL) or network sockets.
1. You can dynamically attach to a running process and stream the code coverage in real-time without terminating process or recompiling the project.