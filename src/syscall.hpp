#ifndef H_SYSCALL_DATA_H
#define H_SYSCALL_DATA_H

#include <cstdint>

#define SYSCALL_MAXARGS 6

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

#endif