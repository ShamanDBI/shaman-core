#include <stdio.h>
#include <sys/types.h>

void rec_fork() {
    fork();
    fork();
    fork();
    printf("hello\n");
}

int fork_exec()
{
    int i = 0;
    long sum;
    int pid;
    int status, ret;
    char *myargs [] = { "Hello", "Fork", "Child", NULL };
    char *myenv [] = { NULL };

    printf ("Parent: Hello, World!\n");

    pid = fork ();

    if (pid == 0) {

        // I am the child

        execve ("/bin/echo", myargs, myenv);
    }

    // I am the parent

    printf ("Parent: Waiting for Child to complete.\n");

    if ((ret = waitpid (pid, &status, 0)) == -1)
         printf ("parent:error\n");

    if (ret == pid)
        printf ("Parent: Child process waited for.\n");
}

void forkexample()
{
    // child process because return value zero
    if (fork() == 0)
        printf("Hello from Child!\n");
  
    // parent process because return value non-zero.
    else
        printf("Hello from Parent!\n");
}

int main(int argc, char *argv[])
{
    int test_case_idx = 1;
    
    if(argc > 1) {
        test_case_idx = atoi(argv[1]);
    }

    switch(test_case_idx) {
        case 1:
            rec_fork();
        break;
        case 2:
            forkexample();
        break;
        case 3:
            fork_exec();
            break;
        default:
            printf("Unknown test case ID\n");
        break;
    }
    return 0;
}