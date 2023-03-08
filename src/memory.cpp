// #include "memory.hpp"
#include <cstdint>
#include <cstdlib>
#include <sys/ptrace.h>
#include <cstring>
#include <sys/types.h>

#include <sys/user.h>
#include <sstream>
#include <elf.h>
#include "stdio.h"

#include "memory.hpp"

using namespace std;


int RemoteMemory::read(Addr *dest, size_t readSize) {
    
    unsigned int bytes_read = 0;
    long * read_addr = (long *) dest->r_addr;
    long * copy_addr = (long *) dest->addr;
    unsigned long ret;
    memset(dest->addr, '\0', readSize);

    do {
        ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
        // printf("RD : %p\n", ret);
        *(copy_addr++) = ret;
        bytes_read += sizeof(long);
    } while(ret && bytes_read < (readSize - sizeof(long)));
    
    return bytes_read;

}

int RemoteMemory::write(Addr *data, size_t writeSize) {

    uint32_t bytes_write = 0;
    long * write_addr = (long *) data->r_addr;
    long * copy_addr = (long *) data->addr;
    long ret;
    
    do {
        ret = ptrace(PTRACE_POKEDATA, m_pid, (write_addr++), *(copy_addr++));
        // printf("WD : %lu \t", ret);
        bytes_write += sizeof(long);
        // printf("%lu %lu %d\n", bytes_write , (writeSize - sizeof(long)), ret > -1);
    } while((ret > -1 )&& bytes_write < (writeSize - sizeof(long)));
    
    return bytes_write;
}

int RemoteMemory::read_cstring(Addr *data) {
    return 0;
}
