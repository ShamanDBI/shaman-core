#ifndef H_SYSCALL_DATA_H
#define H_SYSCALL_DATA_H

#include <cstdint>
#include <string>

#define SYSCALL_MAXARGS 6
#define MAX_SYSCALL_NUM 540

enum sysarg_t
{
  ARG_INT,
  ARG_PTR,
  ARG_STR,
  ARG_UNKNOWN
};

struct SyscallEntry
{
  const char *name;
  uint8_t nargs;
  // SYSCALL_ID args[SYSCALL_MAXARGS];
};

// Link : https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html
// All the System Call defination can be found in syscall.tbl file of the linux kernel
extern SyscallEntry syscalls[MAX_SYSCALL_NUM];

enum class AMD64_SYSCALL : int16_t {
  READ = 0,
  WRITE = 1,
  OPEN = 2,
  CLOSE = 3,
  NEWSTAT = 4,
  NEWFSTAT = 5,
  NEWLSTAT = 6,
  POLL = 7,
  LSEEK = 8,
  MMAP = 9,
  MPROTECT = 10,
  MUNMAP = 11,
  BRK = 12,
  RT_SIGACTION = 13,
  RT_SIGPROCMASK = 14,
  RT_SIGRETURN = 15,
  IOCTL = 16,
  PREAD64 = 17,
  PWRITE64 = 18,
  READV = 19,
  WRITEV = 20,
  ACCESS = 21,
  PIPE = 22,
  SELECT = 23,
  SCHED_YIELD = 24,
  MREMAP = 25,
  MSYNC = 26,
  MINCORE = 27,
  MADVISE = 28,
  SHMGET = 29,
  SHMAT = 30,
  SHMCTL = 31,
  DUP = 32,
  DUP2 = 33,
  PAUSE = 34,
  NANOSLEEP = 35,
  GETITIMER = 36,
  ALARM = 37,
  SETITIMER = 38,
  GETPID = 39,
  SENDFILE64 = 40,
  SOCKET = 41,
  CONNECT = 42,
  ACCEPT = 43,
  SENDTO = 44,
  RECVFROM = 45,
  SENDMSG = 46,
  RECVMSG = 47,
  SHUTDOWN = 48,
  BIND = 49,
  LISTEN = 50,
  GETSOCKNAME = 51,
  GETPEERNAME = 52,
  SOCKETPAIR = 53,
  SETSOCKOPT = 54,
  GETSOCKOPT = 55,
  CLONE = 56,
  FORK = 57,
  VFORK = 58,
  EXECVE = 59,
  EXIT = 60,
  WAIT4 = 61,
  KILL = 62,
  UNAME = 63,
  SEMGET = 64,
  SEMOP = 65,
  SEMCTL = 66,
  SHMDT = 67,
  MSGGET = 68,
  MSGSND = 69,
  MSGRCV = 70,
  MSGCTL = 71,
  FCNTL = 72,
  FLOCK = 73,
  FSYNC = 74,
  FDATASYNC = 75,
  TRUNCATE = 76,
  FTRUNCATE = 77,
  GETDENTS = 78,
  GETCWD = 79,
  CHDIR = 80,
  FCHDIR = 81,
  RENAME = 82,
  MKDIR = 83,
  RMDIR = 84,
  CREAT = 85,
  LINK = 86,
  UNLINK = 87,
  SYMLINK = 88,
  READLINK = 89,
  CHMOD = 90,
  FCHMOD = 91,
  CHOWN = 92,
  FCHOWN = 93,
  LCHOWN = 94,
  UMASK = 95,
  GETTIMEOFDAY = 96,
  GETRLIMIT = 97,
  GETRUSAGE = 98,
  SYSINFO = 99,
  TIMES = 100,
  PTRACE = 101,
  GETUID = 102,
  SYSLOG = 103,
  GETGID = 104,
  SETUID = 105,
  SETGID = 106,
  GETEUID = 107,
  GETEGID = 108,
  SETPGID = 109,
  GETPPID = 110,
  GETPGRP = 111,
  SETSID = 112,
  SETREUID = 113,
  SETREGID = 114,
  GETGROUPS = 115,
  SETGROUPS = 116,
  SETRESUID = 117,
  GETRESUID = 118,
  SETRESGID = 119,
  GETRESGID = 120,
  GETPGID = 121,
  SETFSUID = 122,
  SETFSGID = 123,
  GETSID = 124,
  CAPGET = 125,
  CAPSET = 126,
  RT_SIGPENDING = 127,
  RT_SIGTIMEDWAIT = 128,
  RT_SIGQUEUEINFO = 129,
  RT_SIGSUSPEND = 130,
  SIGALTSTACK = 131,
  UTIME = 132,
  MKNOD = 133,
  PERSONALITY = 135,
  USTAT = 136,
  STATFS = 137,
  FSTATFS = 138,
  SYSFS = 139,
  GETPRIORITY = 140,
  SETPRIORITY = 141,
  SCHED_SETPARAM = 142,
  SCHED_GETPARAM = 143,
  SCHED_SETSCHEDULER = 144,
  SCHED_GETSCHEDULER = 145,
  SCHED_GET_PRIORITY_MAX = 146,
  SCHED_GET_PRIORITY_MIN = 147,
  SCHED_RR_GET_INTERVAL = 148,
  MLOCK = 149,
  MUNLOCK = 150,
  MLOCKALL = 151,
  MUNLOCKALL = 152,
  VHANGUP = 153,
  MODIFY_LDT = 154,
  PIVOT_ROOT = 155,
  SYSCTL = 156,
  PRCTL = 157,
  ARCH_PRCTL = 158,
  ADJTIMEX = 159,
  SETRLIMIT = 160,
  CHROOT = 161,
  SYNC = 162,
  ACCT = 163,
  SETTIMEOFDAY = 164,
  MOUNT = 165,
  UMOUNT = 166,
  SWAPON = 167,
  SWAPOFF = 168,
  REBOOT = 169,
  SETHOSTNAME = 170,
  SETDOMAINNAME = 171,
  IOPL = 172,
  IOPERM = 173,
  INIT_MODULE = 175,
  DELETE_MODULE = 176,
  QUOTACTL = 179,
  NFSSERVCTL = 180,
  GETTID = 186,
  READAHEAD = 187,
  SETXATTR = 188,
  LSETXATTR = 189,
  FSETXATTR = 190,
  GETXATTR = 191,
  LGETXATTR = 192,
  FGETXATTR = 193,
  LISTXATTR = 194,
  LLISTXATTR = 195,
  FLISTXATTR = 196,
  REMOVEXATTR = 197,
  LREMOVEXATTR = 198,
  FREMOVEXATTR = 199,
  TKILL = 200,
  TIME = 201,
  FUTEX = 202,
  SCHED_SETAFFINITY = 203,
  SCHED_GETAFFINITY = 204,
  IO_SETUP = 206,
  IO_DESTROY = 207,
  IO_GETEVENTS = 208,
  IO_SUBMIT = 209,
  IO_CANCEL = 210,
  LOOKUP_DCOOKIE = 212,
  EPOLL_CREATE = 213,
  REMAP_FILE_PAGES = 216,
  GETDENTS64 = 217,
  SET_TID_ADDRESS = 218,
  RESTART_SYSCALL = 219,
  SEMTIMEDOP = 220,
  FADVISE64 = 221,
  TIMER_CREATE = 222,
  TIMER_SETTIME = 223,
  TIMER_GETTIME = 224,
  TIMER_GETOVERRUN = 225,
  TIMER_DELETE = 226,
  CLOCK_SETTIME = 227,
  CLOCK_GETTIME = 228,
  CLOCK_GETRES = 229,
  CLOCK_NANOSLEEP = 230,
  EXIT_GROUP = 231,
  EPOLL_WAIT = 232,
  EPOLL_CTL = 233,
  TGKILL = 234,
  UTIMES = 235,
  MBIND = 237,
  SET_MEMPOLICY = 238,
  GET_MEMPOLICY = 239,
  MQ_OPEN = 240,
  MQ_UNLINK = 241,
  MQ_TIMEDSEND = 242,
  MQ_TIMEDRECEIVE = 243,
  MQ_NOTIFY = 244,
  MQ_GETSETATTR = 245,
  KEXEC_LOAD = 246,
  WAITID = 247,
  ADD_KEY = 248,
  REQUEST_KEY = 249,
  KEYCTL = 250,
  IOPRIO_SET = 251,
  IOPRIO_GET = 252,
  INOTIFY_INIT = 253,
  INOTIFY_ADD_WATCH = 254,
  INOTIFY_RM_WATCH = 255,
  MIGRATE_PAGES = 256,
  OPENAT = 257,
  MKDIRAT = 258,
  MKNODAT = 259,
  FCHOWNAT = 260,
  FUTIMESAT = 261,
  NEWFSTATAT = 262,
  UNLINKAT = 263,
  RENAMEAT = 264,
  LINKAT = 265,
  SYMLINKAT = 266,
  READLINKAT = 267,
  FCHMODAT = 268,
  FACCESSAT = 269,
  PSELECT6 = 270,
  PPOLL = 271,
  UNSHARE = 272,
  SET_ROBUST_LIST = 273,
  GET_ROBUST_LIST = 274,
  SPLICE = 275,
  TEE = 276,
  SYNC_FILE_RANGE = 277,
  VMSPLICE = 278,
  MOVE_PAGES = 279,
  PIPE2 = 293,
  GETRANDOM = 318,
  MAX_CALL = 279
};


enum class AMD64_X32_SYSCALL : uint32_t {
  AMD64_X32_SYSCALL_BIT = 0x40000000,
  READ = (AMD64_X32_SYSCALL_BIT + 0),
  WRITE = (AMD64_X32_SYSCALL_BIT + 1),
  OPEN = (AMD64_X32_SYSCALL_BIT + 2),
  CLOSE = (AMD64_X32_SYSCALL_BIT + 3),
  NEWSTAT = (AMD64_X32_SYSCALL_BIT + 4),
  NEWFSTAT = (AMD64_X32_SYSCALL_BIT + 5),
  NEWLSTAT = (AMD64_X32_SYSCALL_BIT + 6),
  POLL = (AMD64_X32_SYSCALL_BIT + 7),
  LSEEK = (AMD64_X32_SYSCALL_BIT + 8),
  MMAP = (AMD64_X32_SYSCALL_BIT + 9),
  MPROTECT = (AMD64_X32_SYSCALL_BIT + 10),
  MUNMAP = (AMD64_X32_SYSCALL_BIT + 11),
  BRK = (AMD64_X32_SYSCALL_BIT + 12),
  RT_SIGPROCMASK = (AMD64_X32_SYSCALL_BIT + 14),
  PREAD64 = (AMD64_X32_SYSCALL_BIT + 17),
  PWRITE64 = (AMD64_X32_SYSCALL_BIT + 18),
  ACCESS = (AMD64_X32_SYSCALL_BIT + 21),
  PIPE = (AMD64_X32_SYSCALL_BIT + 22),
  SELECT = (AMD64_X32_SYSCALL_BIT + 23),
  SCHED_YIELD = (AMD64_X32_SYSCALL_BIT + 24),
  MREMAP = (AMD64_X32_SYSCALL_BIT + 25),
  MSYNC = (AMD64_X32_SYSCALL_BIT + 26),
  MINCORE = (AMD64_X32_SYSCALL_BIT + 27),
  MADVISE = (AMD64_X32_SYSCALL_BIT + 28),
  SHMGET = (AMD64_X32_SYSCALL_BIT + 29),
  SHMAT = (AMD64_X32_SYSCALL_BIT + 30),
  SHMCTL = (AMD64_X32_SYSCALL_BIT + 31),
  DUP = (AMD64_X32_SYSCALL_BIT + 32),
  DUP2 = (AMD64_X32_SYSCALL_BIT + 33),
  PAUSE = (AMD64_X32_SYSCALL_BIT + 34),
  NANOSLEEP = (AMD64_X32_SYSCALL_BIT + 35),
  GETITIMER = (AMD64_X32_SYSCALL_BIT + 36),
  ALARM = (AMD64_X32_SYSCALL_BIT + 37),
  SETITIMER = (AMD64_X32_SYSCALL_BIT + 38),
  GETPID = (AMD64_X32_SYSCALL_BIT + 39),
  SENDFILE64 = (AMD64_X32_SYSCALL_BIT + 40),
  SOCKET = (AMD64_X32_SYSCALL_BIT + 41),
  CONNECT = (AMD64_X32_SYSCALL_BIT + 42),
  ACCEPT = (AMD64_X32_SYSCALL_BIT + 43),
  SENDTO = (AMD64_X32_SYSCALL_BIT + 44),
  SHUTDOWN = (AMD64_X32_SYSCALL_BIT + 48),
  BIND = (AMD64_X32_SYSCALL_BIT + 49),
  LISTEN = (AMD64_X32_SYSCALL_BIT + 50),
  GETSOCKNAME = (AMD64_X32_SYSCALL_BIT + 51),
  GETPEERNAME = (AMD64_X32_SYSCALL_BIT + 52),
  SOCKETPAIR = (AMD64_X32_SYSCALL_BIT + 53),
  CLONE = (AMD64_X32_SYSCALL_BIT + 56),
  FORK = (AMD64_X32_SYSCALL_BIT + 57),
  VFORK = (AMD64_X32_SYSCALL_BIT + 58),
  EXIT = (AMD64_X32_SYSCALL_BIT + 60),
  WAIT4 = (AMD64_X32_SYSCALL_BIT + 61),
  KILL = (AMD64_X32_SYSCALL_BIT + 62),
  UNAME = (AMD64_X32_SYSCALL_BIT + 63),
  SEMGET = (AMD64_X32_SYSCALL_BIT + 64),
  SEMOP = (AMD64_X32_SYSCALL_BIT + 65),
  SEMCTL = (AMD64_X32_SYSCALL_BIT + 66),
  SHMDT = (AMD64_X32_SYSCALL_BIT + 67),
  MSGGET = (AMD64_X32_SYSCALL_BIT + 68),
  MSGSND = (AMD64_X32_SYSCALL_BIT + 69),
  MSGRCV = (AMD64_X32_SYSCALL_BIT + 70),
  MSGCTL = (AMD64_X32_SYSCALL_BIT + 71),
  FCNTL = (AMD64_X32_SYSCALL_BIT + 72),
  FLOCK = (AMD64_X32_SYSCALL_BIT + 73),
  FSYNC = (AMD64_X32_SYSCALL_BIT + 74),
  FDATASYNC = (AMD64_X32_SYSCALL_BIT + 75),
  TRUNCATE = (AMD64_X32_SYSCALL_BIT + 76),
  FTRUNCATE = (AMD64_X32_SYSCALL_BIT + 77),
  GETDENTS = (AMD64_X32_SYSCALL_BIT + 78),
  GETCWD = (AMD64_X32_SYSCALL_BIT + 79),
  CHDIR = (AMD64_X32_SYSCALL_BIT + 80),
  FCHDIR = (AMD64_X32_SYSCALL_BIT + 81),
  RENAME = (AMD64_X32_SYSCALL_BIT + 82),
  MKDIR = (AMD64_X32_SYSCALL_BIT + 83),
  RMDIR = (AMD64_X32_SYSCALL_BIT + 84),
  CREAT = (AMD64_X32_SYSCALL_BIT + 85),
  LINK = (AMD64_X32_SYSCALL_BIT + 86),
  UNLINK = (AMD64_X32_SYSCALL_BIT + 87),
  SYMLINK = (AMD64_X32_SYSCALL_BIT + 88),
  READLINK = (AMD64_X32_SYSCALL_BIT + 89),
  CHMOD = (AMD64_X32_SYSCALL_BIT + 90),
  FCHMOD = (AMD64_X32_SYSCALL_BIT + 91),
  CHOWN = (AMD64_X32_SYSCALL_BIT + 92),
  FCHOWN = (AMD64_X32_SYSCALL_BIT + 93),
  LCHOWN = (AMD64_X32_SYSCALL_BIT + 94),
  UMASK = (AMD64_X32_SYSCALL_BIT + 95),
  GETTIMEOFDAY = (AMD64_X32_SYSCALL_BIT + 96),
  GETRLIMIT = (AMD64_X32_SYSCALL_BIT + 97),
  GETRUSAGE = (AMD64_X32_SYSCALL_BIT + 98),
  SYSINFO = (AMD64_X32_SYSCALL_BIT + 99),
  TIMES = (AMD64_X32_SYSCALL_BIT + 100),
  GETUID = (AMD64_X32_SYSCALL_BIT + 102),
  SYSLOG = (AMD64_X32_SYSCALL_BIT + 103),
  GETGID = (AMD64_X32_SYSCALL_BIT + 104),
  SETUID = (AMD64_X32_SYSCALL_BIT + 105),
  SETGID = (AMD64_X32_SYSCALL_BIT + 106),
  GETEUID = (AMD64_X32_SYSCALL_BIT + 107),
  GETEGID = (AMD64_X32_SYSCALL_BIT + 108),
  SETPGID = (AMD64_X32_SYSCALL_BIT + 109),
  GETPPID = (AMD64_X32_SYSCALL_BIT + 110),
  GETPGRP = (AMD64_X32_SYSCALL_BIT + 111),
  SETSID = (AMD64_X32_SYSCALL_BIT + 112),
  SETREUID = (AMD64_X32_SYSCALL_BIT + 113),
  SETREGID = (AMD64_X32_SYSCALL_BIT + 114),
  GETGROUPS = (AMD64_X32_SYSCALL_BIT + 115),
  SETGROUPS = (AMD64_X32_SYSCALL_BIT + 116),
  SETRESUID = (AMD64_X32_SYSCALL_BIT + 117),
  GETRESUID = (AMD64_X32_SYSCALL_BIT + 118),
  SETRESGID = (AMD64_X32_SYSCALL_BIT + 119),
  GETRESGID = (AMD64_X32_SYSCALL_BIT + 120),
  GETPGID = (AMD64_X32_SYSCALL_BIT + 121),
  SETFSUID = (AMD64_X32_SYSCALL_BIT + 122),
  SETFSGID = (AMD64_X32_SYSCALL_BIT + 123),
  GETSID = (AMD64_X32_SYSCALL_BIT + 124),
  CAPGET = (AMD64_X32_SYSCALL_BIT + 125),
  CAPSET = (AMD64_X32_SYSCALL_BIT + 126),
  RT_SIGSUSPEND = (AMD64_X32_SYSCALL_BIT + 130),
  UTIME = (AMD64_X32_SYSCALL_BIT + 132),
  MKNOD = (AMD64_X32_SYSCALL_BIT + 133),
  PERSONALITY = (AMD64_X32_SYSCALL_BIT + 135),
  USTAT = (AMD64_X32_SYSCALL_BIT + 136),
  STATFS = (AMD64_X32_SYSCALL_BIT + 137),
  FSTATFS = (AMD64_X32_SYSCALL_BIT + 138),
  SYSFS = (AMD64_X32_SYSCALL_BIT + 139),
  GETPRIORITY = (AMD64_X32_SYSCALL_BIT + 140),
  SETPRIORITY = (AMD64_X32_SYSCALL_BIT + 141),
  SCHED_SETPARAM = (AMD64_X32_SYSCALL_BIT + 142),
  SCHED_GETPARAM = (AMD64_X32_SYSCALL_BIT + 143),
  SCHED_SETSCHEDULER = (AMD64_X32_SYSCALL_BIT + 144),
  SCHED_GETSCHEDULER = (AMD64_X32_SYSCALL_BIT + 145),
  SCHED_GET_PRIORITY_MAX = (AMD64_X32_SYSCALL_BIT + 146),
  SCHED_GET_PRIORITY_MIN = (AMD64_X32_SYSCALL_BIT + 147),
  SCHED_RR_GET_INTERVAL = (AMD64_X32_SYSCALL_BIT + 148),
  MLOCK = (AMD64_X32_SYSCALL_BIT + 149),
  MUNLOCK = (AMD64_X32_SYSCALL_BIT + 150),
  MLOCKALL = (AMD64_X32_SYSCALL_BIT + 151),
  MUNLOCKALL = (AMD64_X32_SYSCALL_BIT + 152),
  VHANGUP = (AMD64_X32_SYSCALL_BIT + 153),
  MODIFY_LDT = (AMD64_X32_SYSCALL_BIT + 154),
  PIVOT_ROOT = (AMD64_X32_SYSCALL_BIT + 155),
  SYSCTL = (AMD64_X32_SYSCALL_BIT + 156),
  PRCTL = (AMD64_X32_SYSCALL_BIT + 157),
  ARCH_PRCTL = (AMD64_X32_SYSCALL_BIT + 158),
  ADJTIMEX = (AMD64_X32_SYSCALL_BIT + 159),
  SETRLIMIT = (AMD64_X32_SYSCALL_BIT + 160),
  CHROOT = (AMD64_X32_SYSCALL_BIT + 161),
  SYNC = (AMD64_X32_SYSCALL_BIT + 162),
  ACCT = (AMD64_X32_SYSCALL_BIT + 163),
  SETTIMEOFDAY = (AMD64_X32_SYSCALL_BIT + 164),
  MOUNT = (AMD64_X32_SYSCALL_BIT + 165),
  UMOUNT = (AMD64_X32_SYSCALL_BIT + 166),
  SWAPON = (AMD64_X32_SYSCALL_BIT + 167),
  SWAPOFF = (AMD64_X32_SYSCALL_BIT + 168),
  REBOOT = (AMD64_X32_SYSCALL_BIT + 169),
  SETHOSTNAME = (AMD64_X32_SYSCALL_BIT + 170),
  SETDOMAINNAME = (AMD64_X32_SYSCALL_BIT + 171),
  IOPL = (AMD64_X32_SYSCALL_BIT + 172),
  IOPERM = (AMD64_X32_SYSCALL_BIT + 173),
  INIT_MODULE = (AMD64_X32_SYSCALL_BIT + 175),
  DELETE_MODULE = (AMD64_X32_SYSCALL_BIT + 176),
  QUOTACTL = (AMD64_X32_SYSCALL_BIT + 179),
  GETTID = (AMD64_X32_SYSCALL_BIT + 186),
  READAHEAD = (AMD64_X32_SYSCALL_BIT + 187),
  SETXATTR = (AMD64_X32_SYSCALL_BIT + 188),
  LSETXATTR = (AMD64_X32_SYSCALL_BIT + 189),
  FSETXATTR = (AMD64_X32_SYSCALL_BIT + 190),
  GETXATTR = (AMD64_X32_SYSCALL_BIT + 191),
  LGETXATTR = (AMD64_X32_SYSCALL_BIT + 192),
  FGETXATTR = (AMD64_X32_SYSCALL_BIT + 193),
  LISTXATTR = (AMD64_X32_SYSCALL_BIT + 194),
  LLISTXATTR = (AMD64_X32_SYSCALL_BIT + 195),
  FLISTXATTR = (AMD64_X32_SYSCALL_BIT + 196),
  REMOVEXATTR = (AMD64_X32_SYSCALL_BIT + 197),
  LREMOVEXATTR = (AMD64_X32_SYSCALL_BIT + 198),
  FREMOVEXATTR = (AMD64_X32_SYSCALL_BIT + 199),
  TKILL = (AMD64_X32_SYSCALL_BIT + 200),
  TIME = (AMD64_X32_SYSCALL_BIT + 201),
  FUTEX = (AMD64_X32_SYSCALL_BIT + 202),
  SCHED_SETAFFINITY = (AMD64_X32_SYSCALL_BIT + 203),
  SCHED_GETAFFINITY = (AMD64_X32_SYSCALL_BIT + 204),
  IO_SETUP = (AMD64_X32_SYSCALL_BIT + 206),
  IO_DESTROY = (AMD64_X32_SYSCALL_BIT + 207),
  IO_GETEVENTS = (AMD64_X32_SYSCALL_BIT + 208),
  IO_SUBMIT = (AMD64_X32_SYSCALL_BIT + 209),
  IO_CANCEL = (AMD64_X32_SYSCALL_BIT + 210),
  LOOKUP_DCOOKIE = (AMD64_X32_SYSCALL_BIT + 212),
  EPOLL_CREATE = (AMD64_X32_SYSCALL_BIT + 213),
  REMAP_FILE_PAGES = (AMD64_X32_SYSCALL_BIT + 216),
  GETDENTS64 = (AMD64_X32_SYSCALL_BIT + 217),
  SET_TID_ADDRESS = (AMD64_X32_SYSCALL_BIT + 218),
  RESTART_SYSCALL = (AMD64_X32_SYSCALL_BIT + 219),
  SEMTIMEDOP = (AMD64_X32_SYSCALL_BIT + 220),
  FADVISE64 = (AMD64_X32_SYSCALL_BIT + 221),
  TIMER_SETTIME = (AMD64_X32_SYSCALL_BIT + 223),
  TIMER_GETTIME = (AMD64_X32_SYSCALL_BIT + 224),
  TIMER_GETOVERRUN = (AMD64_X32_SYSCALL_BIT + 225),
  TIMER_DELETE = (AMD64_X32_SYSCALL_BIT + 226),
  CLOCK_SETTIME = (AMD64_X32_SYSCALL_BIT + 227),
  CLOCK_GETTIME = (AMD64_X32_SYSCALL_BIT + 228),
  CLOCK_GETRES = (AMD64_X32_SYSCALL_BIT + 229),
  CLOCK_NANOSLEEP = (AMD64_X32_SYSCALL_BIT + 230),
  EXIT_GROUP = (AMD64_X32_SYSCALL_BIT + 231),
  EPOLL_WAIT = (AMD64_X32_SYSCALL_BIT + 232),
  EPOLL_CTL = (AMD64_X32_SYSCALL_BIT + 233),
  TGKILL = (AMD64_X32_SYSCALL_BIT + 234),
  UTIMES = (AMD64_X32_SYSCALL_BIT + 235),
  MBIND = (AMD64_X32_SYSCALL_BIT + 237),
  SET_MEMPOLICY = (AMD64_X32_SYSCALL_BIT + 238),
  GET_MEMPOLICY = (AMD64_X32_SYSCALL_BIT + 239),
  MQ_OPEN = (AMD64_X32_SYSCALL_BIT + 240),
  MQ_UNLINK = (AMD64_X32_SYSCALL_BIT + 241),
  MQ_TIMEDSEND = (AMD64_X32_SYSCALL_BIT + 242),
  MQ_TIMEDRECEIVE = (AMD64_X32_SYSCALL_BIT + 243),
  MQ_GETSETATTR = (AMD64_X32_SYSCALL_BIT + 245),
  ADD_KEY = (AMD64_X32_SYSCALL_BIT + 248),
  REQUEST_KEY = (AMD64_X32_SYSCALL_BIT + 249),
  KEYCTL = (AMD64_X32_SYSCALL_BIT + 250),
  IOPRIO_SET = (AMD64_X32_SYSCALL_BIT + 251),
  IOPRIO_GET = (AMD64_X32_SYSCALL_BIT + 252),
  INOTIFY_INIT = (AMD64_X32_SYSCALL_BIT + 253),
  INOTIFY_ADD_WATCH = (AMD64_X32_SYSCALL_BIT + 254),
  INOTIFY_RM_WATCH = (AMD64_X32_SYSCALL_BIT + 255),
  MIGRATE_PAGES = (AMD64_X32_SYSCALL_BIT + 256),
  OPENAT = (AMD64_X32_SYSCALL_BIT + 257),
  MKDIRAT = (AMD64_X32_SYSCALL_BIT + 258),
  MKNODAT = (AMD64_X32_SYSCALL_BIT + 259),
  FCHOWNAT = (AMD64_X32_SYSCALL_BIT + 260),
  FUTIMESAT = (AMD64_X32_SYSCALL_BIT + 261),
  NEWFSTATAT = (AMD64_X32_SYSCALL_BIT + 262),
  UNLINKAT = (AMD64_X32_SYSCALL_BIT + 263),
  RENAMEAT = (AMD64_X32_SYSCALL_BIT + 264),
  LINKAT = (AMD64_X32_SYSCALL_BIT + 265),
  SYMLINKAT = (AMD64_X32_SYSCALL_BIT + 266),
  READLINKAT = (AMD64_X32_SYSCALL_BIT + 267),
  FCHMODAT = (AMD64_X32_SYSCALL_BIT + 268),
  FACCESSAT = (AMD64_X32_SYSCALL_BIT + 269),
  PSELECT6 = (AMD64_X32_SYSCALL_BIT + 270),
  PPOLL = (AMD64_X32_SYSCALL_BIT + 271),
  UNSHARE = (AMD64_X32_SYSCALL_BIT + 272),
  SPLICE = (AMD64_X32_SYSCALL_BIT + 275),
  TEE = (AMD64_X32_SYSCALL_BIT + 276),
  SYNC_FILE_RANGE = (AMD64_X32_SYSCALL_BIT + 277),
  RT_SIGACTION = (AMD64_X32_SYSCALL_BIT + 512),
  RT_SIGRETURN = (AMD64_X32_SYSCALL_BIT + 513),
  IOCTL = (AMD64_X32_SYSCALL_BIT + 514),
  READV = (AMD64_X32_SYSCALL_BIT + 515),
  WRITEV = (AMD64_X32_SYSCALL_BIT + 516),
  RECVFROM = (AMD64_X32_SYSCALL_BIT + 517),
  SENDMSG = (AMD64_X32_SYSCALL_BIT + 518),
  RECVMSG = (AMD64_X32_SYSCALL_BIT + 519),
  EXECVE = (AMD64_X32_SYSCALL_BIT + 520),
  PTRACE = (AMD64_X32_SYSCALL_BIT + 521),
  RT_SIGPENDING = (AMD64_X32_SYSCALL_BIT + 522),
  RT_SIGTIMEDWAIT = (AMD64_X32_SYSCALL_BIT + 523),
  RT_SIGQUEUEINFO = (AMD64_X32_SYSCALL_BIT + 524),
  SIGALTSTACK = (AMD64_X32_SYSCALL_BIT + 525),
  TIMER_CREATE = (AMD64_X32_SYSCALL_BIT + 526),
  MQ_NOTIFY = (AMD64_X32_SYSCALL_BIT + 527),
  KEXEC_LOAD = (AMD64_X32_SYSCALL_BIT + 528),
  WAITID = (AMD64_X32_SYSCALL_BIT + 529),
  SET_ROBUST_LIST = (AMD64_X32_SYSCALL_BIT + 530),
  GET_ROBUST_LIST = (AMD64_X32_SYSCALL_BIT + 531),
  VMSPLICE = (AMD64_X32_SYSCALL_BIT + 532),
  MOVE_PAGES = (AMD64_X32_SYSCALL_BIT + 533),
  PREADV = (AMD64_X32_SYSCALL_BIT + 534),
  PWRITEV = (AMD64_X32_SYSCALL_BIT + 535),
  RT_TGSIGQUEUEINFO = (AMD64_X32_SYSCALL_BIT + 536),
  RECVMMSG = (AMD64_X32_SYSCALL_BIT + 537),
  SENDMMSG = (AMD64_X32_SYSCALL_BIT + 538),
  PROCESS_VM_READV = (AMD64_X32_SYSCALL_BIT + 539),
  PROCESS_VM_WRITEV = (AMD64_X32_SYSCALL_BIT + 540),
  SETSOCKOPT = (AMD64_X32_SYSCALL_BIT + 541),
  GETSOCKOPT = (AMD64_X32_SYSCALL_BIT + 542)
};

enum class ARM64_SYSCALL : int16_t {
    IO_SETUP = 0,
    IO_DESTROY = 1,
    IO_SUBMIT = 2,
    IO_CANCEL = 3,
    IO_GETEVENTS = 4,
    SETXATTR = 5,
    LSETXATTR = 6,
    FSETXATTR = 7,
    GETXATTR = 8,
    LGETXATTR = 9,
    FGETXATTR = 10,
    LISTXATTR = 11,
    LLISTXATTR = 12,
    FLISTXATTR = 13,
    REMOVEXATTR = 14,
    LREMOVEXATTR = 15,
    FREMOVEXATTR = 16,
    GETCWD = 17,
    LOOKUP_DCOOKIE = 18,
    EVENTFD2 = 19,
    EPOLL_CREATE1 = 20,
    EPOLL_CTL = 21,
    EPOLL_PWAIT = 22,
    DUP = 23,
    DUP3 = 24,
    FCNTL = 25,
    INOTIFY_INIT1 = 26,
    INOTIFY_ADD_WATCH = 27,
    INOTIFY_RM_WATCH = 28,
    IOCTL = 29,
    IOPRIO_SET = 30,
    IOPRIO_GET = 31,
    FLOCK = 32,
    MKNODAT = 33,
    MKDIRAT = 34,
    UNLINKAT = 35,
    SYMLINKAT = 36,
    LINKAT = 37,
    RENAMEAT = 38,
    UMOUNT2 = 39,
    MOUNT = 40,
    PIVOT_ROOT = 41,
    NFSSERVCTL = 42,
    STATFS = 43,
    FSTATFS = 44,
    TRUNCATE = 45,
    FTRUNCATE = 46,
    FALLOCATE = 47,
    FACCESSAT = 48,
    CHDIR = 49,
    FCHDIR = 50,
    CHROOT = 51,
    FCHMOD = 52,
    FCHMODAT = 53,
    FCHOWNAT = 54,
    FCHOWN = 55,
    OPENAT = 56,
    CLOSE = 57,
    VHANGUP = 58,
    PIPE2 = 59,
    QUOTACTL = 60,
    GETDENTS64 = 61,
    LSEEK = 62,
    READ = 63,
    WRITE = 64,
    READV = 65,
    WRITEV = 66,
    PREAD64 = 67,
    PWRITE64 = 68,
    PREADV = 69,
    PWRITEV = 70,
    SENDFILE = 71,
    PSELECT6 = 72,
    PPOLL = 73,
    SIGNALFD4 = 74,
    VMSPLICE = 75,
    SPLICE = 76,
    TEE = 77,
    READLINKAT = 78,
    NEWFSTATAT = 79,
    FSTAT = 80,
    SYNC = 81,
    FSYNC = 82,
    FDATASYNC = 83,
    SYNC_FILE_RANGE2 = 84,
    SYNC_FILE_RANGE = 84,
    TIMERFD_CREATE = 85,
    TIMERFD_SETTIME = 86,
    TIMERFD_GETTIME = 87,
    UTIMENSAT = 88,
    ACCT = 89,
    CAPGET = 90,
    CAPSET = 91,
    PERSONALITY = 92,
    EXIT = 93,
    EXIT_GROUP = 94,
    WAITID = 95,
    SET_TID_ADDRESS = 96,
    UNSHARE = 97,
    FUTEX = 98,
    SET_ROBUST_LIST = 99,
    GET_ROBUST_LIST = 100,
    NANOSLEEP = 101,
    GETITIMER = 102,
    SETITIMER = 103,
    KEXEC_LOAD = 104,
    INIT_MODULE = 105,
    DELETE_MODULE = 106,
    TIMER_CREATE = 107,
    TIMER_GETTIME = 108,
    TIMER_GETOVERRUN = 109,
    TIMER_SETTIME = 110,
    TIMER_DELETE = 111,
    CLOCK_SETTIME = 112,
    CLOCK_GETTIME = 113,
    CLOCK_GETRES = 114,
    CLOCK_NANOSLEEP = 115,
    SYSLOG = 116,
    PTRACE = 117,
    SCHED_SETPARAM = 118,
    SCHED_SETSCHEDULER = 119,
    SCHED_GETSCHEDULER = 120,
    SCHED_GETPARAM = 121,
    SCHED_SETAFFINITY = 122,
    SCHED_GETAFFINITY = 123,
    SCHED_YIELD = 124,
    SCHED_GET_PRIORITY_MAX = 125,
    SCHED_GET_PRIORITY_MIN = 126,
    SCHED_RR_GET_INTERVAL = 127,
    KILL = 129,
    TKILL = 130,
    TGKILL = 131,
    SIGALTSTACK = 132,
    RT_SIGSUSPEND = 133,
    RT_SIGACTION = 134,
    RT_SIGPROCMASK = 135,
    RT_SIGPENDING = 136,
    RT_SIGTIMEDWAIT = 137,
    RT_SIGQUEUEINFO = 138,
    RT_SIGRETURN = 139,
    SETPRIORITY = 140,
    GETPRIORITY = 141,
    REBOOT = 142,
    SETREGID = 143,
    SETGID = 144,
    SETREUID = 145,
    SETUID = 146,
    SETRESUID = 147,
    GETRESUID = 148,
    SETRESGID = 149,
    GETRESGID = 150,
    SETFSUID = 151,
    SETFSGID = 152,
    TIMES = 153,
    SETPGID = 154,
    GETPGID = 155,
    GETSID = 156,
    SETSID = 157,
    GETGROUPS = 158,
    SETGROUPS = 159,
    UNAME = 160,
    SETHOSTNAME = 161,
    SETDOMAINNAME = 162,
    GETRLIMIT = 163,
    SETRLIMIT = 164,
    GETRUSAGE = 165,
    UMASK = 166,
    PRCTL = 167,
    GETCPU = 168,
    GETTIMEOFDAY = 169,
    SETTIMEOFDAY = 170,
    ADJTIMEX = 171,
    GETPID = 172,
    GETPPID = 173,
    GETUID = 174,
    GETEUID = 175,
    GETGID = 176,
    GETEGID = 177,
    GETTID = 178,
    SYSINFO = 179,
    MQ_OPEN = 180,
    MQ_UNLINK = 181,
    MQ_TIMEDSEND = 182,
    MQ_TIMEDRECEIVE = 183,
    MQ_NOTIFY = 184,
    MQ_GETSETATTR = 185,
    MSGGET = 186,
    MSGCTL = 187,
    MSGRCV = 188,
    MSGSND = 189,
    SEMGET = 190,
    SEMCTL = 191,
    SEMTIMEDOP = 192,
    SEMOP = 193,
    SHMGET = 194,
    SHMCTL = 195,
    SHMAT = 196,
    SHMDT = 197,
    SOCKET = 198,
    SOCKETPAIR = 199,
    BIND = 200,
    LISTEN = 201,
    ACCEPT = 202,
    CONNECT = 203,
    GETSOCKNAME = 204,
    GETPEERNAME = 205,
    SENDTO = 206,
    RECVFROM = 207,
    SETSOCKOPT = 208,
    GETSOCKOPT = 209,
    SHUTDOWN = 210,
    SENDMSG = 211,
    RECVMSG = 212,
    READAHEAD = 213,
    BRK = 214,
    MUNMAP = 215,
    MREMAP = 216,
    ADD_KEY = 217,
    REQUEST_KEY = 218,
    KEYCTL = 219,
    CLONE = 220,
    EXECVE = 221,
    MMAP = 222,
    FADVISE64 = 223,
    SWAPON = 224,
    SWAPOFF = 225,
    MPROTECT = 226,
    MSYNC = 227,
    MLOCK = 228,
    MUNLOCK = 229,
    MLOCKALL = 230,
    MUNLOCKALL = 231,
    MINCORE = 232,
    MADVISE = 233,
    REMAP_FILE_PAGES = 234,
    MBIND = 235,
    GET_MEMPOLICY = 236,
    SET_MEMPOLICY = 237,
    MIGRATE_PAGES = 238,
    MOVE_PAGES = 239,
    RT_TGSIGQUEUEINFO = 240,
    PERF_EVENT_OPEN = 241,
    ACCEPT4 = 242,
    RECVMMSG = 243,
    WAIT4 = 260,
    PRLIMIT64 = 261,
    FANOTIFY_INIT = 262,
    FANOTIFY_MARK = 263,
    NAME_TO_HANDLE_AT = 264,
    OPEN_BY_HANDLE_AT = 265,
    CLOCK_ADJTIME = 266,
    SYNCFS = 267,
    SETNS = 268,
    SENDMMSG = 269,
    PROCESS_VM_READV = 270,
    PROCESS_VM_WRITEV = 271,
    KCMP = 272,
    FINIT_MODULE = 273,
    SCHED_SETATTR = 274,
    SCHED_GETATTR = 275,
    GETRANDOM = 278,
    MAX_CALL = 279,
    RSEQ = 293
};

/* An unknown GDB syscall, not a real syscall.  */
class SysCallId {

public:
  enum syscall_no : std::int16_t
  {

    NO_SYSCALL = -1,

    RESTART_SYSCALL = 0,
    EXIT = 1,
    FORK = 2,
    READ = 3,
    WRITE = 4,
    OPEN = 5,
    CLOSE = 6,
    WAITPID = 7,
    CREAT = 8,
    LINK = 9,
    UNLINK = 10,
    EXECVE = 11,
    CHDIR = 12,
    TIME = 13,
    MKNOD = 14,
    CHMOD = 15,
    LCHOWN16 = 16,
    NI_SYSCALL17 = 17,
    STAT = 18,
    LSEEK = 19,
    GETPID = 20,
    MOUNT = 21,
    OLDUMOUNT = 22,
    SETUID16 = 23,
    GETUID16 = 24,
    STIME = 25,
    PTRACE = 26,
    ALARM = 27,
    FSTAT = 28,
    PAUSE = 29,
    UTIME = 30,
    NI_SYSCALL31 = 31,
    NI_SYSCALL32 = 32,
    ACCESS = 33,
    NICE = 34,
    NI_SYSCALL35 = 35,
    SYNC = 36,
    KILL = 37,
    RENAME = 38,
    MKDIR = 39,
    RMDIR = 40,
    DUP = 41,
    PIPE = 42,
    TIMES = 43,
    NI_SYSCALL44 = 44,
    BRK = 45,
    SETGID16 = 46,
    GETGID16 = 47,
    SIGNAL = 48,
    GETEUID16 = 49,
    GETEGID16 = 50,
    ACCT = 51,
    UMOUNT = 52,
    NI_SYSCALL53 = 53,
    IOCTL = 54,
    FCNTL = 55,
    NI_SYSCALL56 = 56,
    SETPGID = 57,
    NI_SYSCALL58 = 58,
    OLDUNAME = 59,
    UMASK = 60,
    CHROOT = 61,
    USTAT = 62,
    DUP2 = 63,
    GETPPID = 64,
    GETPGRP = 65,
    SETSID = 66,
    SIGACTION = 67,
    SGETMASK = 68,
    SSETMASK = 69,
    SETREUID16 = 70,
    SETREGID16 = 71,
    SIGSUSPEND = 72,
    SIGPENDING = 73,
    SETHOSTNAME = 74,
    SETRLIMIT = 75,
    OLD_GETRLIMIT = 76,
    GETRUSAGE = 77,
    GETTIMEOFDAY = 78,
    SETTIMEOFDAY = 79,
    GETGROUPS16 = 80,
    SETGROUPS16 = 81,
    OLD_SELECT = 82,
    SYMLINK = 83,
    LSTAT = 84,
    READLINK = 85,
    USELIB = 86,
    SWAPON = 87,
    REBOOT = 88,
    OLD_READDIR = 89,
    OLD_MMAP = 90,
    MUNMAP = 91,
    TRUNCATE = 92,
    FTRUNCATE = 93,
    FCHMOD = 94,
    FCHOWN16 = 95,
    GETPRIORITY = 96,
    SETPRIORITY = 97,
    NI_SYSCALL98 = 98,
    STATFS = 99,
    FSTATFS = 100,
    IOPERM = 101,
    SOCKETCALL = 102,
    SYSLOG = 103,
    SETITIMER = 104,
    GETITIMER = 105,
    NEWSTAT = 106,
    NEWLSTAT = 107,
    NEWFSTAT = 108,
    UNAME = 109,
    IOPL = 110,
    VHANGUP = 111,
    NI_SYSCALL112 = 112,
    VM86OLD = 113,
    WAIT4 = 114,
    SWAPOFF = 115,
    SYSINFO = 116,
    IPC = 117,
    FSYNC = 118,
    SIGRETURN = 119,
    CLONE = 120,
    SETDOMAINNAME = 121,
    NEWUNAME = 122,
    MODIFY_LDT = 123,
    ADJTIMEX = 124,
    MPROTECT = 125,
    SIGPROCMASK = 126,
    NI_SYSCALL127 = 127,
    INIT_MODULE = 128,
    DELETE_MODULE = 129,
    NI_SYSCALL130 = 130,
    QUOTACTL = 131,
    GETPGID = 132,
    FCHDIR = 133,
    BDFLUSH = 134,
    SYSFS = 135,
    PERSONALITY = 136,
    NI_SYSCALL137 = 137,
    SETFSUID16 = 138,
    SETFSGID16 = 139,
    LLSEEK = 140,
    GETDENTS = 141,
    SELECT = 142,
    FLOCK = 143,
    MSYNC = 144,
    READV = 145,
    WRITEV = 146,
    GETSID = 147,
    FDATASYNC = 148,
    SYSCTL = 149,
    MLOCK = 150,
    MUNLOCK = 151,
    MLOCKALL = 152,
    MUNLOCKALL = 153,
    SCHED_SETPARAM = 154,
    SCHED_GETPARAM = 155,
    SCHED_SETSCHEDULER = 156,
    SCHED_GETSCHEDULER = 157,
    SCHED_YIELD = 158,
    SCHED_GET_PRIORITY_MAX = 159,
    SCHED_GET_PRIORITY_MIN = 160,
    SCHED_RR_GET_INTERVAL = 161,
    NANOSLEEP = 162,
    MREMAP = 163,
    SETRESUID16 = 164,
    GETRESUID16 = 165,
    VM86 = 166,
    NI_SYSCALL167 = 167,
    POLL = 168,
    NFSSERVCTL = 169,
    SETRESGID16 = 170,
    GETRESGID16 = 171,
    PRCTL = 172,
    RT_SIGRETURN = 173,
    RT_SIGACTION = 174,
    RT_SIGPROCMASK = 175,
    RT_SIGPENDING = 176,
    RT_SIGTIMEDWAIT = 177,
    RT_SIGQUEUEINFO = 178,
    RT_SIGSUSPEND = 179,
    PREAD64 = 180,
    PWRITE64 = 181,
    CHOWN16 = 182,
    GETCWD = 183,
    CAPGET = 184,
    CAPSET = 185,
    SIGALTSTACK = 186,
    SENDFILE = 187,
    NI_SYSCALL188 = 188,
    NI_SYSCALL189 = 189,
    VFORK = 190,
    GETRLIMIT = 191,
    MMAP2 = 192,
    TRUNCATE64 = 193,
    FTRUNCATE64 = 194,
    STAT64 = 195,
    LSTAT64 = 196,
    FSTAT64 = 197,
    LCHOWN = 198,
    GETUID = 199,
    GETGID = 200,
    GETEUID = 201,
    GETEGID = 202,
    SETREUID = 203,
    SETREGID = 204,
    GETGROUPS = 205,
    SETGROUPS = 206,
    FCHOWN = 207,
    SETRESUID = 208,
    GETRESUID = 209,
    SETRESGID = 210,
    GETRESGID = 211,
    CHOWN = 212,
    SETUID = 213,
    SETGID = 214,
    SETFSUID = 215,
    SETFSGID = 216,
    PIVOT_ROOT = 217,
    MINCORE = 218,
    MADVISE = 219,
    GETDENTS64 = 220,
    FCNTL64 = 221,
    NI_SYSCALL222 = 222,
    NI_SYSCALL223 = 223,
    GETTID = 224,
    READAHEAD = 225,
    SETXATTR = 226,
    LSETXATTR = 227,
    FSETXATTR = 228,
    GETXATTR = 229,
    LGETXATTR = 230,
    FGETXATTR = 231,
    LISTXATTR = 232,
    LLISTXATTR = 233,
    FLISTXATTR = 234,
    REMOVEXATTR = 235,
    LREMOVEXATTR = 236,
    FREMOVEXATTR = 237,
    TKILL = 238,
    SENDFILE64 = 239,
    FUTEX = 240,
    SCHED_SETAFFINITY = 241,
    SCHED_GETAFFINITY = 242,
    SET_THREAD_AREA = 243,
    GET_THREAD_AREA = 244,
    IO_SETUP = 245,
    IO_DESTROY = 246,
    IO_GETEVENTS = 247,
    IO_SUBMIT = 248,
    IO_CANCEL = 249,
    FADVISE64 = 250,
    NI_SYSCALL251 = 251,
    EXIT_GROUP = 252,
    LOOKUP_DCOOKIE = 253,
    EPOLL_CREATE = 254,
    EPOLL_CTL = 255,
    EPOLL_WAIT = 256,
    REMAP_FILE_PAGES = 257,
    SET_TID_ADDRESS = 258,
    TIMER_CREATE = 259,
    TIMER_SETTIME = 260,
    TIMER_GETTIME = 261,
    TIMER_GETOVERRUN = 262,
    TIMER_DELETE = 263,
    CLOCK_SETTIME = 264,
    CLOCK_GETTIME = 265,
    CLOCK_GETRES = 266,
    CLOCK_NANOSLEEP = 267,
    STATFS64 = 268,
    FSTATFS64 = 269,
    TGKILL = 270,
    UTIMES = 271,
    FADVISE64_64 = 272,
    NI_SYSCALL273 = 273,
    MBIND = 274,
    GET_MEMPOLICY = 275,
    SET_MEMPOLICY = 276,
    MQ_OPEN = 277,
    MQ_UNLINK = 278,
    MQ_TIMEDSEND = 279,
    MQ_TIMEDRECEIVE = 280,
    MQ_NOTIFY = 281,
    MQ_GETSETATTR = 282,
    KEXEC_LOAD = 283,
    WAITID = 284,
    NI_SYSCALL285 = 285,
    ADD_KEY = 286,
    REQUEST_KEY = 287,
    KEYCTL = 288,
    IOPRIO_SET = 289,
    IOPRIO_GET = 290,
    INOTIFY_INIT = 291,
    INOTIFY_ADD_WATCH = 292,
    INOTIFY_RM_WATCH = 293,
    MIGRATE_PAGES = 294,
    OPENAT = 295,
    MKDIRAT = 296,
    MKNODAT = 297,
    FCHOWNAT = 298,
    FUTIMESAT = 299,
    FSTATAT64 = 300,
    UNLINKAT = 301,
    RENAMEAT = 302,
    LINKAT = 303,
    SYMLINKAT = 304,
    READLINKAT = 305,
    FCHMODAT = 306,
    FACCESSAT = 307,
    PSELECT6 = 308,
    PPOLL = 309,
    UNSHARE = 310,
    SET_ROBUST_LIST = 311,
    GET_ROBUST_LIST = 312,
    SPLICE = 313,
    SYNC_FILE_RANGE = 314,
    TEE = 315,
    VMSPLICE = 316,
    MOVE_PAGES = 317,
    GETCPU = 318,
    EPOLL_PWAIT = 319,
    FALLOCATE = 324,
    EVENTFD2 = 328,
    EPOLL_CREATE1 = 329,
    DUP3 = 330,
    PIPE2 = 331,
    INOTIFY_INIT1 = 332,
    GETRANDOM = 355,
    STATX = 383,
    PRLIMIT64 = 384,
    SOCKET = 500,
    CONNECT = 501,
    ACCEPT = 502,
    SENDTO = 503,
    RECVFROM = 504,
    SENDMSG = 505,
    RECVMSG = 506,
    SHUTDOWN = 507,
    BIND = 508,
    LISTEN = 509,
    GETSOCKNAME = 510,
    GETPEERNAME = 511,
    SOCKETPAIR = 512,
    SETSOCKOPT = 513,
    GETSOCKOPT = 514,
    RECV = 515,
    SHMGET = 520,
    SHMAT = 521,
    SHMCTL = 522,
    SEMGET = 523,
    SEMOP = 524,
    SEMCTL = 525,
    SHMDT = 527,
    MSGGET = 528,
    MSGSND = 529,
    MSGRCV = 530,
    MSGCTL = 531,
    SEMTIMEDOP = 532,
    NEWFSTATAT = 540,
    // this is an architecture specific system call using 
    // to set and get architecture specific registers like
    // FS , GS and CPUID etc.
    RSEQ = 541,
    ARCH_PRCTL = 542,
    PREAD = 543,
    PREADV = 544,
    PWRITE = 545,
    PWRITEV = 546
    // LSEEK = 544
  };

  SysCallId() : m_syscall_value(NO_SYSCALL) {};

  SysCallId(int16_t _syscall_id) {
    m_syscall_value = static_cast<syscall_no>(_syscall_id);
  }

  constexpr SysCallId(syscall_no _syscall_id) : m_syscall_value(_syscall_id) {}

  virtual ~SysCallId() {
    m_syscall_value = NO_SYSCALL;
  };

  SysCallId& operator=(const SysCallId &syscall) {
    m_syscall_value = syscall.getValue();
    return *this;
  }

  std::string getString() const;

  bool hasValue(syscall_no value);
  
  syscall_no getValue() const;
  
  int16_t getIntValue() { 
    return static_cast<int16_t>(m_syscall_value); 
  };

  bool operator==(const SysCallId& rhs) const;
  bool operator!=(const SysCallId& rhs) const;

  bool operator<(const SysCallId& otherObj) {
    return m_syscall_value < otherObj.m_syscall_value;
  };

  void setValue(int16_t _syscall_id) {
    m_syscall_value = static_cast<syscall_no>(_syscall_id);
  };

  size_t hash() const {
      return std::hash<std::int16_t>()(m_syscall_value);
  }

private:
  syscall_no m_syscall_value = NO_SYSCALL;
};



/**
 * Note the above enum implementation has been taken from below blog
 * https://medium.com/@niedoba.lukas/next-level-c-enums-a5208fbc0190
*/

#endif