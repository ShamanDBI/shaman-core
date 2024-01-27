#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>

void *do_loop(void *data)
{

    int i;
    int j;
    uint64_t global_cnt = 0;
    int me = *((int *)data);

    if (me == 1)
    {
        for (i = 0; i < 100; i++)
        {
            for (uint64_t j = 0; j < 0xffff; j++)
            {
                global_cnt++;
            };
            printf("Thread id : %d - Got %d\n", me, i);
        }
    }
    else
    {
        for (i = 0; i < 100; i++)
        {
            for (uint64_t j = 0; j < 0xffff; j++)
            {
                global_cnt++;
            };
            printf("Other Thread id : %d - Got %d\n", me, i);
        }
    }
    /* terminate the thread */
    pthread_exit(NULL);
}

void print_hex(uint8_t *buf, size_t buf_size)
{
    for (int i = 0; i < buf_size; i++)
    {
        printf("%02X ", buf[i]);
        if ((i + 1) % 32 == 0)
        {
            printf("\n");
        }
    }
}

void read_random_data(uint32_t data_size)
{
    printf("Read and print Random Data test, Data size %d\n", data_size);
    char* rand_data_buf = calloc(1, data_size);
    int rand_fd = open("/dev/random", O_RDONLY);
    if (rand_fd < 0)
    {
        printf("Error Opening /dev/random");
        return;
    }
    else
    {
        size_t rand_data_left = 0;
        while (rand_data_left < data_size)
        {
            ssize_t result = read(rand_fd, rand_data_buf + rand_data_left, data_size - rand_data_left);
            if (result < 0)
            {
                printf("Error reading randome data");
            }
            rand_data_left += result;
        }
        print_hex(rand_data_buf, data_size);
        printf("\n");
        close(rand_fd);
    }
    free(rand_data_buf);
}

void real_infinite_loop()
{
    pid_t tid = gettid();
    void *mem_alloc = mmap(
        NULL,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    printf("Allocated memory %p\n", mem_alloc);
    while (1)
    {
        printf("[%d] I just woke up, again!\n", tid);
        sleep(3);
    }
}

void do_infinite_loop(void *data)
{
    size_t counter = 5000;
    // pid_t tid = syscall(SYS_gettid);
    pid_t tid = gettid();

    while (counter)
    {
        printf("[%d] Thead %lu\n", tid, counter);
        sleep(0.5);
        counter--;
    }
}

void test_computed_calls(void *param)
{
    int *_param = (int *)param;

    int test_id = _param[0];
    switch (test_id)
    {
    case 1:
        printf("This is the string %d\n", test_id);
        break;
    case 2:
        printf("This is case 2 string %d\n", test_id);
        break;
    case 3:
        printf("This is case 3 string %d\n", test_id);
        break;
    case 4:
        printf("This is case 4 string %d\n", test_id);
        break;
    case 5:
        printf("This is case 5 string %d\n", test_id);
        break;
    default:
        printf("This is an invalid call %d\n", test_id);
        break;
    }
    printf("This param 2 %d\n", _param[1]);
}

void test_threaded_computed_calls()
{
#define NUM_OF_THREADS 50
    int thr_id;                         /* thread ID for the newly created thread */
    pthread_t p_thread[NUM_OF_THREADS]; /* thread's structure                     */
    int a = 1;                          /* thread 1 identifying number            */
    int b = 1;                          /* thread 2 identifying number            */

    for (int i = 0; i < NUM_OF_THREADS; i++)
    {
        int *param = (int *)malloc(2 * sizeof(int));
        param[0] = rand() % 6;
        param[1] = rand();
        thr_id = pthread_create(&p_thread[i], NULL, test_computed_calls, (void *)param);
        printf("New Thread created with id : %d\n", thr_id);
    }

    for (int i = 0; i < NUM_OF_THREADS; i++)
    {
        pthread_join(p_thread[i], NULL);
    }
    return 0;
}

void test_infinite_threads()
{
#define NUM_OF_THREADS 50
    int thr_id;                         /* thread ID for the newly created thread */
    pthread_t p_thread[NUM_OF_THREADS]; /* thread's structure                     */
    int a = 1;                          /* thread 1 identifying number            */
    int b = 1;                          /* thread 2 identifying number            */

    for (int i = 0; i < NUM_OF_THREADS; i++)
    {
        thr_id = pthread_create(&p_thread[i], NULL, do_infinite_loop, (void *)&a);
        printf("New Thread created with id : %d\n", thr_id);
    }

    for (int i = 0; i < NUM_OF_THREADS; i++)
    {
        pthread_join(p_thread[i], NULL);
    }
    return 0;
}

int test_multi_threading_same_section()
{
    /**
     * TODO : This is pending issue we have to fix this use case
     * with this test case we are testing use case we have placed breakpoint
     * on and two threads are running same section of the code
     */
    int thr_id;         /* thread ID for the newly created thread */
    pthread_t p_thread; /* thread's structure                     */
    int a = 1;          /* thread 1 identifying number            */
    int b = 1;          /* thread 2 identifying number            */

    /* create a new thread that will execute 'do_loop()' */
    thr_id = pthread_create(&p_thread, NULL, do_loop, (void *)&a);
    printf("New Thread created with id : %d\n", thr_id);
    /* run 'do_loop()' in the main thread as well */
    do_loop((void *)&b);
    return 0;
}

int test_multi_threading_different_section()
{
    /**
     * with this test case we are testing use case we have placed breakpoint
     * on and two threads are running two differect section of the code
     */
    int thr_id;         /* thread ID for the newly created thread */
    pthread_t p_thread; /* thread's structure                     */
    int a = 1;          /* thread 1 identifying number            */
    int b = 2;          /* thread 2 identifying number            */

    /* create a new thread that will execute 'do_loop()' */
    thr_id = pthread_create(&p_thread, NULL, do_loop, (void *)&a);
    printf("New Thread created with id : %d\n", thr_id);
    /* run 'do_loop()' in the main thread as well */
    do_loop((void *)&b);
    return 0;
}

void dump_file_content(char *file_path)
{
    char buf[4096];
    ssize_t n;
    char *str = NULL;
    size_t len = 0;
    int fd = open(file_path, O_RDONLY);
    if (fd < 0)
    {
        printf("Cannot Open file : %s\n", file_path);
    }
    printf("File opened %d\n", fd);
    while (n = read(fd, buf, sizeof buf))
    {
        if (n < 0)
        {
            // if (errno == EAGAIN)
            //     continue;
            perror("read");
            break;
        }
        str = realloc(str, len + n + 1);
        memcpy(str + len, buf, n);
        len += n;
        str[len] = '\0';
    }
    printf("%.*s\n", len, str);
    close(fd);
    return 0;
}

void test_file_dumping(char *file_path)
{
    dump_file_content(file_path);
    dump_file_content("/home/hussain/.bashrc");
    dump_file_content(file_path);
}

void test_file_operation()
{
    printf("This is file test program\n");

    int fd = open("/data/local/tmp/hi.txt", O_RDONLY);
    char buf[100];
    read(fd, buf, 10);
    write(fd, buf, 10);
    ioctl(fd, buf, 10);
    printf("This file data is : %s\n", buf);
    close(fd);
}

void test_brk_point()
{
    printf("Helloo.. this is breakpoint test program\n");
    int N = 15;
    int fd = open("/home/hussain/hi.txt", O_RDONLY);
    int *ptr = mmap(NULL, N * sizeof(int), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    printf("Strike Breakpoint 1\n");

    if (ptr == MAP_FAILED)
    {
        printf("Mapping Failed\n");
        return;
    }
    close(fd);
    for (int i = 0; i < N; i++)
    {
        // asm("int $3");
        ptr[i] = i * 10;
    }

    for (int i = 0; i < N; i++)
        printf("[%d] ", ptr[i]);

    printf("Strike Breakpoint 2\n");
    // asm("int $3");
    printf("\n");
    int err = munmap(ptr, 10 * sizeof(int));
    if (err != 0)
    {
        printf("UnMapping Failed\n");
    }
}

void rec_fork()
{
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
    char *myargs[] = {"Hello", "Fork", "Child", NULL};
    char *myenv[] = {NULL};

    printf("Parent: Hello, World!\n");

    pid = fork();

    if (pid == 0)
    {

        // I am the child

        execve("/bin/echo", myargs, myenv);
    }

    // I am the parent

    printf("Parent: Waiting for Child to complete.\n");

    if ((ret = waitpid(pid, &status, 0)) == -1)
        printf("parent:error\n");

    if (ret == pid)
        printf("Parent: Child process waited for.\n");
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

    if (argc > 1)
    {
        test_case_idx = atoi(argv[1]);
    }
    // test_case_idx = 6;
    switch (test_case_idx)
    {
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
    case 9:
        test_file_dumping(argv[2]);
        break;
    case 10:
        test_threaded_computed_calls();
        break;
    case 11:
        real_infinite_loop();
        break;
    case 12:
        read_random_data(atoi(argv[2]));
        break;
    default:
        printf("Unknown test case ID\n");
        break;
    }
    return 0;
}
