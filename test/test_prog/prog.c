#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>


void* do_loop(void* data) {

    int i;
    int j;
    int me = *((int*)data);

    if (me == 1) {
        for (i=0; i<100; i++) {
            sleep(1);
            printf("Thread id : %d - Got %d\n", me, i);
        }
    } else {
        for (i=0; i<100; i++) {
            sleep(1);
            printf("Other Thread id : %d - Got %d\n", me, i);
        }
    }
    /* terminate the thread */
    pthread_exit(NULL);
}
#include <sys/types.h>

void do_infinite_loop(void * data) {
    size_t counter = 0;
    // pid_t tid = syscall(SYS_gettid);
    pid_t tid = gettid();

    while(1) {
        printf("[%d] Thead %lu\n", tid, counter++);
        sleep(10);
    }
}

void test_infinite_threads() {
    #define NUM_OF_THREADS 100
    int        thr_id;         /* thread ID for the newly created thread */
    pthread_t  p_thread[NUM_OF_THREADS];       /* thread's structure                     */
    int        a         = 1;  /* thread 1 identifying number            */
    int        b         = 1;  /* thread 2 identifying number            */

    for(int i=0; i<NUM_OF_THREADS; i++) {
        thr_id = pthread_create(&p_thread[i], NULL, do_infinite_loop, (void*)&a);
        printf("New Thread created with id : %d\n", thr_id);
    }
    
    for(int i=0;i<100;i++) {
        pthread_join(p_thread[i], NULL);
    }
    return 0;
}

int test_multi_threading_same_section() {
    /**
     * TODO : This is pending issue we have to fix this use case
     * with this test case we are testing use case we have placed breakpoint
     * on and two threads are running same section of the code
    */
    int        thr_id;         /* thread ID for the newly created thread */
    pthread_t  p_thread;       /* thread's structure                     */
    int        a         = 1;  /* thread 1 identifying number            */
    int        b         = 1;  /* thread 2 identifying number            */

    /* create a new thread that will execute 'do_loop()' */
    thr_id = pthread_create(&p_thread, NULL, do_loop, (void*)&a);
    printf("New Thread created with id : %d\n", thr_id);
    /* run 'do_loop()' in the main thread as well */
    do_loop((void*)&b);
    return 0;
}


int test_multi_threading_different_section() {
    /**
     * with this test case we are testing use case we have placed breakpoint
     * on and two threads are running two differect section of the code
    */
    int        thr_id;         /* thread ID for the newly created thread */
    pthread_t  p_thread;       /* thread's structure                     */
    int        a         = 1;  /* thread 1 identifying number            */
    int        b         = 2;  /* thread 2 identifying number            */

    /* create a new thread that will execute 'do_loop()' */
    thr_id = pthread_create(&p_thread, NULL, do_loop, (void*)&a);
    printf("New Thread created with id : %d\n", thr_id);
    /* run 'do_loop()' in the main thread as well */
    do_loop((void*)&b);
    return 0;
}


void test_file_operation() {
    printf("This is file test program\n");
    
    int fd = open("/home/hussain/hi.txt", O_RDONLY);
    char buf[100];
    read(fd, buf, 10);
    write(fd, buf, 10);
    ioctl(fd, buf, 10);
    printf("This file data is : %s\n", buf);
    close(fd);
}

void test_brk_point() {
    printf("Helloo.. this is breakpoint test program\n");
    int N=15;
    int fd = open("/home/hussain/hi.txt", O_RDONLY);
    int *ptr = mmap ( NULL, N*sizeof(int), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0 );
    
    printf("Strike Breakpoint 1\n");

    if(ptr == MAP_FAILED){
        printf("Mapping Failed\n");
        return;
    }
    close(fd);
    for(int i=0; i<N; i++) {
        // asm("int $3");
        ptr[i] = i*10;
    }

    for(int i=0; i<N; i++)
        printf("[%d] ",ptr[i]);

    printf("Strike Breakpoint 2\n");
    // asm("int $3");
    printf("\n");
    int err = munmap(ptr, 10*sizeof(int));
    if(err != 0){
        printf("UnMapping Failed\n");
    }
}

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
    test_case_idx = 6;
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
        case 4:
            test_brk_point();
            break;
        case 5:
            test_file_operation();
            break;
        case 6:
            test_multi_threading_different_section();
            break;
        case 7:
            test_multi_threading_same_section();
            break;
        case 8:
            test_infinite_threads();
            break;
        default:
            printf("Unknown test case ID\n");
        break;
    }
    return 0;
}