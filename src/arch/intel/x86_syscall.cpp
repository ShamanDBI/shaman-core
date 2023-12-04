#include "syscall.hpp"

#define X86_SYSCALL_MAX 499

SysCallId i386_canonicalize_syscall(int16_t syscall_id) {
    if (syscall_id <= X86_SYSCALL_MAX) {
        return SysCallId(syscall_id);
    } else {
        return SysCallId::NO_SYSCALL;
    }
}