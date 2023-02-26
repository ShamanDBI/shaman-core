#ifndef H_SYSCALL_DATA_H
#define H_SYSCALL_DATA_H

#include <cstdint>

#define SYSCALL_MAXARGS 6
#define MAX_SYSCALL_NUM 311

enum sysarg_t {
  ARG_INT,
  ARG_PTR,
  ARG_STR,
  ARG_UNKNOWN
};

struct SyscallEntry {
  const char *name;
  uint8_t nargs;
  sysarg_t args[SYSCALL_MAXARGS];
};

using sysc_id_t = uint16_t;

extern SyscallEntry syscalls[MAX_SYSCALL_NUM];

#endif