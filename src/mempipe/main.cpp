#include <iostream>
#include "mempipe.hpp"

#define IPC_ID 0xcafe1

int DataProcess(uint8_t *buffer, uint32_t buffer_len)
{
    printf("Processing Data : ptr %p of len %d", buffer, buffer_len);

    for (int i = 0; i < buffer_len; i++)
    {
        printf("%hx ", buffer[i]);
        if (!(i % 16))
            printf("\n");
    }
    printf("\n");
    return 0;
}

void ParentWork()
{
    printf("We are in parent\n");
    char rand_data[128] = {0};
    auto ss_pipe = new SendPipe<CURR_CHUNK_SIZE, CURR_NUM_BUFFER>();
    MemPipeError res = ss_pipe->create(IPC_ID);

    if (res != MemPipeError::ResultOk)
    {
        printf("Error opening shared Memory!");
    }
    printf("IPC socket opened successfully!\n");
    int rand_fd = open("/dev/urandom", O_RDONLY);

    while (1)
    {

        auto chunk_writer = ss_pipe->allocateBuffer(false);
        printf("We have the chunk %p\n", chunk_writer->data());
        read(rand_fd, rand_data, sizeof(rand_data));
        chunk_writer->send((uint8_t *)&rand_data, sizeof(rand_data));
        chunk_writer->drop();
        // sleep(1);
        chunk_writer.reset();
    }
    printf("Good Bye!\n");
}

void ChildWork()
{

    printf("We are in child\n");
    auto rec_pipe = new RecvPipe<CURR_CHUNK_SIZE, CURR_NUM_BUFFER>();
    MemPipeError res = rec_pipe->open(IPC_ID);
    if (res != MemPipeError::ResultOk)
    {
        printf("Shared Memory Error Id %d\n", res);
        return;
    }

    Ticket tk = rec_pipe->requestTicket();
    Ticket new_tk = 0;
    while(1)
    {
        sleep(3);
        rec_pipe->try_recv(tk, &DataProcess, &new_tk);
        if (tk != new_tk)
        {
            printf("New Ticket Id : %lu\n", new_tk);
        }
        tk = new_tk;
    }
}

int main(int argc, char *argv[])
{

    int cpid = 0;
    cpid = fork(); /* fork() returns the child process's PID  */

    printf("First child pid %d\n", cpid);
    if (cpid == 0)
    {
        printf("ddd\n");
    } else {
        ParentWork();
    }

    for (int i = 0; i < 10; i++)
    {
        if (cpid == 0)
        {
            ChildWork();
        }
        else
        {
            cpid = fork();
            if (cpid == -1) /* An error has occurred. */
            {
                fprintf(stderr, "%s", "The call to fork() has failed.\n");
                exit(EXIT_FAILURE);
            }
            printf("Child Pid : %d %d\n", cpid, i);
        }
    }
}