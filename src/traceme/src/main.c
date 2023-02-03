#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <elf.h>
#include "arm64_syscall.h"
#include <wait.h>
// #define NT_PRSTATUS	1

void run_dbg(pid_t tracee_pid);
void run_prog(const char* prog_path);

int main(int argc, char** argv)
{
    pid_t tracee_pid;

    if(argc < 2)
    {
        printf("Expected a program name as argument\n");
        return -1;
    }

    tracee_pid = fork(); 

    if (tracee_pid == 0)
        run_prog(argv[1]);
    else if (tracee_pid > 0)
        run_dbg(tracee_pid);
    else 
    {
        perror("fork");
        return -1;
    }

    return 0;
}


void run_prog(const char* prog_path)
{
    printf("target started. will run '%s'\n", prog_path);

    /* Allow tracing of this process */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        perror("fail to attach debugger to the process");
        return;
    }

    /* Replace this process's image with the given program */
    execl(prog_path, prog_path, 0);
}

void get_gp_reg(struct user_pt_regs *regs, pid_t tracee_pid) {
    struct iovec io;

    io.iov_base = regs;
    io.iov_len = sizeof(struct user_pt_regs);

    if (ptrace(PTRACE_GETREGSET, tracee_pid, (void*)NT_PRSTATUS, (void*)&io) == -1)
        printf("BAD REGISTER REQUEST\n");

    // unsigned instr = ptrace(PTRACE_PEEKTEXT, tracee_pid, regs.pc, 0);

    // for(int i=0 ; i<8; i++) {
    //     printf("reg[%d] %ld ", i, regs->regs[i]);
    // }
    // printf("\n");

    // printf("PC = 0x%08x  sp = 0x%08x pstate=%08x\n", regs->pc, regs->sp, regs->pstate);
}

uint64_t read_mem(pid_t tracee_pid, uint64_t addr) {
    uint64_t data = ptrace(PTRACE_PEEKTEXT, tracee_pid, addr, 0);
    printf("addr=%p  val = %d\n", addr, data);
    return data;
}

void next_exec(pid_t tracee_pid) {

    // if (ptrace(PTRACE_CONT, tracee_pid, NULL, 0)) {
    // {
    //     printf("PTRACE_CONT failed!");
    //     return;
    // }

    /* Make the child execute another instruction */
    if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) < 0) 
    {
        printf("PTRACE_SYSCALL failed!");
        return;
    }
}
void handle_syscall(pid_t tracee_pid) {
    char open_path[100] = {0};
    struct user_pt_regs regs = {0};
    get_gp_reg(&regs, tracee_pid);
    uint32_t syscall_id = regs.regs[0];
    uint64_t file_path_ptr, fd, buf_addr;
    // printf("Sys Call %ld ", syscall_id);
    switch(syscall_id) {
        case __NR_open:
            // file_path_ptr = regs.regs[1];
            // printf("open(0x%x) \n", file_path_ptr);
            // if(file_path_ptr != 0)
            //     read_mem(tracee_pid, file_path_ptr);
                // printf("%d\n", read_mem(tracee_pid, file_path_ptr));
        break;
        case __NR_fork:
            // printf("fork\n");
        break;
        case __NR_ioctl:
            // printf("ioctl\n");
        break;
        case __NR_read:
            fd = regs.regs[0];
            buf_addr = regs.regs[1];
            printf("read(%d, 0x%lx) \n", fd, buf_addr);
            read_mem(tracee_pid, buf_addr);
            // printf("read\n");
        break;
        case __NR_write:
            // printf("write\n");
        break;
        case __NR_mmap2:
            // printf("mmap2\n");
        break;
        default:
            // printf("Unkown : %d\n", syscall_id);
        break;
    }
}
void run_dbg(pid_t tracee_pid)
{
    int wait_status;
    unsigned icounter = 0;
    printf("Debugger started\n");

    while (1) 
    {
        /* Wait for child to stop on its next instruction */
        // wait(&wait_status);
        waitpid(tracee_pid, &wait_status , __WALL);
        // waitpid(tracee_pid, &wait_status, WNOHANG);
        if (WIFSTOPPED(wait_status)) {

        }
        
		if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
			printf("Child died unexpectedly\n");
            goto disappeared;
        }

        handle_syscall(tracee_pid);
        next_exec(tracee_pid);
    }

    error:
    	kill(tracee_pid, SIGKILL);
    disappeared:
        return ;
}