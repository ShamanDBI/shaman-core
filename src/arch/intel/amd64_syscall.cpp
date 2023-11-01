#include <iostream>
#include "syscall.hpp"


SysCallId amd64_canonicalize_syscall(AMD64_SYSCALL syscall_number)
{
    switch (syscall_number)
    {
      case AMD64_SYSCALL::IO_SETUP:
        return SysCallId::IO_SETUP;
      case AMD64_SYSCALL::IO_DESTROY:
        return SysCallId::IO_DESTROY;
      case AMD64_SYSCALL::IO_SUBMIT:
        return SysCallId::IO_SUBMIT;
      case AMD64_SYSCALL::IO_CANCEL:
        return SysCallId::IO_CANCEL;
      case AMD64_SYSCALL::IO_GETEVENTS:
        return SysCallId::IO_GETEVENTS;
      case AMD64_SYSCALL::SETXATTR:
        return SysCallId::SETXATTR;
      case AMD64_SYSCALL::LSETXATTR:
        return SysCallId::LSETXATTR;
      case AMD64_SYSCALL::FSETXATTR:
        return SysCallId::FSETXATTR;
      case AMD64_SYSCALL::GETXATTR:
        return SysCallId::GETXATTR;
      case AMD64_SYSCALL::LGETXATTR:
        return SysCallId::LGETXATTR;
      case AMD64_SYSCALL::FGETXATTR:
        return SysCallId::FGETXATTR;
      case AMD64_SYSCALL::LISTXATTR:
        return SysCallId::LISTXATTR;
      case AMD64_SYSCALL::LLISTXATTR:
        return SysCallId::LLISTXATTR;
      case AMD64_SYSCALL::FLISTXATTR:
        return SysCallId::FLISTXATTR;
      case AMD64_SYSCALL::REMOVEXATTR:
        return SysCallId::REMOVEXATTR;
      case AMD64_SYSCALL::LREMOVEXATTR:
        return SysCallId::LREMOVEXATTR;
      case AMD64_SYSCALL::FREMOVEXATTR:
        return SysCallId::FREMOVEXATTR;
      case AMD64_SYSCALL::GETCWD:
        return SysCallId::GETCWD;
      case AMD64_SYSCALL::LOOKUP_DCOOKIE:
        return SysCallId::LOOKUP_DCOOKIE;
      case AMD64_SYSCALL::EVENTFD2:
        return SysCallId::EVENTFD2;
      case AMD64_SYSCALL::EPOLL_CREATE1:
        return SysCallId::EPOLL_CREATE1;
      case AMD64_SYSCALL::EPOLL_CTL:
        return SysCallId::EPOLL_CTL;
      case AMD64_SYSCALL::EPOLL_PWAIT:
        return SysCallId::EPOLL_PWAIT;
      case AMD64_SYSCALL::DUP:
        return SysCallId::DUP;
      case AMD64_SYSCALL::DUP3:
        return SysCallId::DUP3;
      case AMD64_SYSCALL::FCNTL:
        return SysCallId::FCNTL;
      case AMD64_SYSCALL::INOTIFY_INIT1:
        return SysCallId::INOTIFY_INIT1;
      case AMD64_SYSCALL::INOTIFY_ADD_WATCH:
        return SysCallId::INOTIFY_ADD_WATCH;
      case AMD64_SYSCALL::INOTIFY_RM_WATCH:
        return SysCallId::INOTIFY_RM_WATCH;
      case AMD64_SYSCALL::IOCTL:
        return SysCallId::IOCTL;
      case AMD64_SYSCALL::IOPRIO_SET:
        return SysCallId::IOPRIO_SET;
      case AMD64_SYSCALL::IOPRIO_GET:
        return SysCallId::IOPRIO_GET;
      case AMD64_SYSCALL::FLOCK:
        return SysCallId::FLOCK;
      case AMD64_SYSCALL::MKNODAT:
        return SysCallId::MKNODAT;
      case AMD64_SYSCALL::MKDIRAT:
        return SysCallId::MKDIRAT;
      case AMD64_SYSCALL::UNLINKAT:
        return SysCallId::UNLINKAT;
      case AMD64_SYSCALL::SYMLINKAT:
        return SysCallId::SYMLINKAT;
      case AMD64_SYSCALL::LINKAT:
        return SysCallId::LINKAT;
      case AMD64_SYSCALL::RENAMEAT:
        return SysCallId::RENAMEAT;
      case AMD64_SYSCALL::UMOUNT2:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::MOUNT:
        return SysCallId::MOUNT;
      case AMD64_SYSCALL::PIVOT_ROOT:
        return SysCallId::PIVOT_ROOT;
      case AMD64_SYSCALL::NFSSERVCTL:
        return SysCallId::NFSSERVCTL;
      case AMD64_SYSCALL::STATFS:
        return SysCallId::STATFS;
      case AMD64_SYSCALL::TRUNCATE:
        return SysCallId::TRUNCATE;
      case AMD64_SYSCALL::FTRUNCATE:
        return SysCallId::FTRUNCATE;
      case AMD64_SYSCALL::FALLOCATE:
        return SysCallId::FALLOCATE;
      case AMD64_SYSCALL::FACCESSAT:
        return SysCallId::FACCESSAT;
      case AMD64_SYSCALL::FCHDIR:
        return SysCallId::FCHDIR;
      case AMD64_SYSCALL::CHROOT:
        return SysCallId::CHROOT;
      case AMD64_SYSCALL::FCHMOD:
        return SysCallId::FCHMOD;
      case AMD64_SYSCALL::FCHMODAT:
        return SysCallId::FCHMODAT;
      case AMD64_SYSCALL::FCHOWNAT:
        return SysCallId::FCHOWNAT;
      case AMD64_SYSCALL::FCHOWN:
        return SysCallId::FCHOWN;
      case AMD64_SYSCALL::OPENAT:
        return SysCallId::OPENAT;
      case AMD64_SYSCALL::CLOSE:
        return SysCallId::CLOSE;
      case AMD64_SYSCALL::VHANGUP:
        return SysCallId::VHANGUP;
      case AMD64_SYSCALL::PIPE2:
        return SysCallId::PIPE2;
      case AMD64_SYSCALL::QUOTACTL:
        return SysCallId::QUOTACTL;
      case AMD64_SYSCALL::GETDENTS64:
        return SysCallId::GETDENTS64;
      case AMD64_SYSCALL::LSEEK:
        return SysCallId::LSEEK;
      case AMD64_SYSCALL::READ:
        return SysCallId::READ;
      case AMD64_SYSCALL::WRITE:
        return SysCallId::WRITE;
      case AMD64_SYSCALL::READV:
        return SysCallId::READV;
      case AMD64_SYSCALL::WRITEV:
        return SysCallId::WRITEV;
      case AMD64_SYSCALL::PREAD64:
        return SysCallId::PREAD64;
      case AMD64_SYSCALL::PWRITE64:
        return SysCallId::PWRITE64;
      case AMD64_SYSCALL::PREADV:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::PWRITEV:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SENDFILE:
        return SysCallId::SENDFILE;
      case AMD64_SYSCALL::PSELECT6:
        return SysCallId::PSELECT6;
      case AMD64_SYSCALL::PPOLL:
        return SysCallId::PPOLL;
      case AMD64_SYSCALL::SIGNALFD4:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::VMSPLICE:
        return SysCallId::VMSPLICE;
      case AMD64_SYSCALL::SPLICE:
        return SysCallId::SPLICE;
      case AMD64_SYSCALL::TEE:
        return SysCallId::TEE;
      case AMD64_SYSCALL::READLINKAT:
        return SysCallId::READLINKAT;
      case AMD64_SYSCALL::NEWFSTATAT:
        return SysCallId::NEWFSTATAT;
      case AMD64_SYSCALL::FSTAT:
        return SysCallId::FSTAT;
      case AMD64_SYSCALL::SYNC:
        return SysCallId::SYNC;
      case AMD64_SYSCALL::FSYNC:
        return SysCallId::FSYNC;
      case AMD64_SYSCALL::FDATASYNC:
        return SysCallId::FDATASYNC;
      case AMD64_SYSCALL::SYNC_FILE_RANGE:
        return SysCallId::SYNC_FILE_RANGE;
      case AMD64_SYSCALL::TIMERFD_CREATE:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::TIMERFD_SETTIME:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::TIMERFD_GETTIME:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::UTIMENSAT:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::ACCT:
        return SysCallId::ACCT;
      case AMD64_SYSCALL::CAPGET:
        return SysCallId::CAPGET;
      case AMD64_SYSCALL::CAPSET:
        return SysCallId::CAPSET;
      case AMD64_SYSCALL::PERSONALITY:
        return SysCallId::PERSONALITY;
      case AMD64_SYSCALL::EXIT:
        return SysCallId::EXIT;
      case AMD64_SYSCALL::EXIT_GROUP:
        return SysCallId::EXIT_GROUP;
      case AMD64_SYSCALL::WAITID:
        return SysCallId::WAITID;
      case AMD64_SYSCALL::SET_TID_ADDRESS:
        return SysCallId::SET_TID_ADDRESS;
      case AMD64_SYSCALL::UNSHARE:
        return SysCallId::UNSHARE;
      case AMD64_SYSCALL::FUTEX:
        return SysCallId::FUTEX;
      case AMD64_SYSCALL::SET_ROBUST_LIST:
        return SysCallId::SET_ROBUST_LIST;
      case AMD64_SYSCALL::GET_ROBUST_LIST:
        return SysCallId::GET_ROBUST_LIST;
      case AMD64_SYSCALL::NANOSLEEP:
        return SysCallId::NANOSLEEP;
      case AMD64_SYSCALL::GETITIMER:
        return SysCallId::GETITIMER;
      case AMD64_SYSCALL::SETITIMER:
        return SysCallId::SETITIMER;
      case AMD64_SYSCALL::KEXEC_LOAD:
        return SysCallId::KEXEC_LOAD;
      case AMD64_SYSCALL::INIT_MODULE:
        return SysCallId::INIT_MODULE;
      case AMD64_SYSCALL::DELETE_MODULE:
        return SysCallId::DELETE_MODULE;
      case AMD64_SYSCALL::TIMER_CREATE:
        return SysCallId::TIMER_CREATE;
      case AMD64_SYSCALL::TIMER_SETTIME:
        return SysCallId::TIMER_SETTIME;
      case AMD64_SYSCALL::TIMER_GETTIME:
        return SysCallId::TIMER_GETTIME;
      case AMD64_SYSCALL::TIMER_GETOVERRUN:
        return SysCallId::TIMER_GETOVERRUN;
      case AMD64_SYSCALL::TIMER_DELETE:
        return SysCallId::TIMER_DELETE;
      case AMD64_SYSCALL::CLOCK_SETTIME:
        return SysCallId::CLOCK_SETTIME;
      case AMD64_SYSCALL::CLOCK_GETTIME:
        return SysCallId::CLOCK_GETTIME;
      case AMD64_SYSCALL::CLOCK_GETRES:
        return SysCallId::CLOCK_GETRES;
      case AMD64_SYSCALL::CLOCK_NANOSLEEP:
        return SysCallId::CLOCK_NANOSLEEP;
      case AMD64_SYSCALL::SYSLOG:
        return SysCallId::SYSLOG;
      case AMD64_SYSCALL::PTRACE:
        return SysCallId::PTRACE;
      case AMD64_SYSCALL::SCHED_SETPARAM:
        return SysCallId::SCHED_SETPARAM;
      case AMD64_SYSCALL::SCHED_SETSCHEDULER:
        return SysCallId::SCHED_SETSCHEDULER;
      case AMD64_SYSCALL::SCHED_GETSCHEDULER:
        return SysCallId::SCHED_GETSCHEDULER;
      case AMD64_SYSCALL::SCHED_GETPARAM:
        return SysCallId::SCHED_GETPARAM;
      case AMD64_SYSCALL::SCHED_SETAFFINITY:
        return SysCallId::SCHED_SETAFFINITY;
      case AMD64_SYSCALL::SCHED_GETAFFINITY:
        return SysCallId::SCHED_GETAFFINITY;
      case AMD64_SYSCALL::SCHED_YIELD:
        return SysCallId::SCHED_YIELD;
      case AMD64_SYSCALL::SCHED_GET_PRIORITY_MAX:
        return SysCallId::SCHED_GET_PRIORITY_MAX;
      case AMD64_SYSCALL::SCHED_GET_PRIORITY_MIN:
        return SysCallId::SCHED_GET_PRIORITY_MIN;
      case AMD64_SYSCALL::SCHED_RR_GET_INTERVAL:
        return SysCallId::SCHED_RR_GET_INTERVAL;
      case AMD64_SYSCALL::KILL:
        return SysCallId::KILL;
      case AMD64_SYSCALL::TKILL:
        return SysCallId::TKILL;
      case AMD64_SYSCALL::TGKILL:
        return SysCallId::TGKILL;
      case AMD64_SYSCALL::SIGALTSTACK:
        return SysCallId::SIGALTSTACK;
      case AMD64_SYSCALL::RT_SIGSUSPEND:
        return SysCallId::RT_SIGSUSPEND;
      case AMD64_SYSCALL::RT_SIGACTION:
        return SysCallId::RT_SIGACTION;
      case AMD64_SYSCALL::RT_SIGPROCMASK:
        return SysCallId::RT_SIGPROCMASK;
      case AMD64_SYSCALL::RT_SIGPENDING:
        return SysCallId::RT_SIGPENDING;
      case AMD64_SYSCALL::RT_SIGTIMEDWAIT:
        return SysCallId::RT_SIGTIMEDWAIT;
      case AMD64_SYSCALL::RT_SIGQUEUEINFO:
        return SysCallId::RT_SIGQUEUEINFO;
      case AMD64_SYSCALL::RT_SIGRETURN:
        return SysCallId::RT_SIGRETURN;
      case AMD64_SYSCALL::SETPRIORITY:
        return SysCallId::SETPRIORITY;
      case AMD64_SYSCALL::GETPRIORITY:
        return SysCallId::GETPRIORITY;
      case AMD64_SYSCALL::REBOOT:
        return SysCallId::REBOOT;
      case AMD64_SYSCALL::SETREGID:
        return SysCallId::SETREGID;
      case AMD64_SYSCALL::SETGID:
        return SysCallId::SETGID;
      case AMD64_SYSCALL::SETREUID:
        return SysCallId::SETREUID;
      case AMD64_SYSCALL::SETUID:
        return SysCallId::SETUID;
      case AMD64_SYSCALL::SETRESUID:
        return SysCallId::SETRESUID;
      case AMD64_SYSCALL::GETRESUID:
        return SysCallId::GETRESUID;
      case AMD64_SYSCALL::SETRESGID:
        return SysCallId::SETRESGID;
      case AMD64_SYSCALL::GETRESGID:
        return SysCallId::GETRESGID;
      case AMD64_SYSCALL::SETFSUID:
        return SysCallId::SETFSUID;
      case AMD64_SYSCALL::SETFSGID:
        return SysCallId::SETFSGID;
      case AMD64_SYSCALL::TIMES:
        return SysCallId::TIMES;
      case AMD64_SYSCALL::SETPGID:
        return SysCallId::SETPGID;
      case AMD64_SYSCALL::GETPGID:
        return SysCallId::GETPGID;
      case AMD64_SYSCALL::GETSID:
        return SysCallId::GETSID;
      case AMD64_SYSCALL::SETSID:
        return SysCallId::SETSID;
      case AMD64_SYSCALL::GETGROUPS:
        return SysCallId::GETGROUPS;
      case AMD64_SYSCALL::SETGROUPS:
        return SysCallId::SETGROUPS;
      case AMD64_SYSCALL::UNAME:
        return SysCallId::UNAME;
      case AMD64_SYSCALL::SETHOSTNAME:
        return SysCallId::SETHOSTNAME;
      case AMD64_SYSCALL::SETDOMAINNAME:
        return SysCallId::SETDOMAINNAME;
      case AMD64_SYSCALL::GETRLIMIT:
        return SysCallId::GETRLIMIT;
      case AMD64_SYSCALL::SETRLIMIT:
        return SysCallId::SETRLIMIT;
      case AMD64_SYSCALL::GETRUSAGE:
        return SysCallId::GETRUSAGE;
      case AMD64_SYSCALL::UMASK:
        return SysCallId::UMASK;
      case AMD64_SYSCALL::PRCTL:
        return SysCallId::PRCTL;
      case AMD64_SYSCALL::GETCPU:
        return SysCallId::GETCPU;
      case AMD64_SYSCALL::GETTIMEOFDAY:
        return SysCallId::GETTIMEOFDAY;
      case AMD64_SYSCALL::SETTIMEOFDAY:
        return SysCallId::SETTIMEOFDAY;
      case AMD64_SYSCALL::ADJTIMEX:
        return SysCallId::ADJTIMEX;
      case AMD64_SYSCALL::GETPID:
        return SysCallId::GETPID;
      case AMD64_SYSCALL::GETPPID:
        return SysCallId::GETPPID;
      case AMD64_SYSCALL::GETUID:
        return SysCallId::GETUID;
      case AMD64_SYSCALL::GETEUID:
        return SysCallId::GETEUID;
      case AMD64_SYSCALL::GETGID:
        return SysCallId::GETGID;
      case AMD64_SYSCALL::GETEGID:
        return SysCallId::GETEGID;
      case AMD64_SYSCALL::GETTID:
        return SysCallId::GETTID;
      case AMD64_SYSCALL::SYSINFO:
        return SysCallId::SYSINFO;
      case AMD64_SYSCALL::MQ_OPEN:
        return SysCallId::MQ_OPEN;
      case AMD64_SYSCALL::MQ_UNLINK:
        return SysCallId::MQ_UNLINK;
      case AMD64_SYSCALL::MQ_TIMEDSEND:
        return SysCallId::MQ_TIMEDSEND;
      case AMD64_SYSCALL::MQ_TIMEDRECEIVE:
        return SysCallId::MQ_TIMEDRECEIVE;
      case AMD64_SYSCALL::MQ_NOTIFY:
        return SysCallId::MQ_NOTIFY;
      case AMD64_SYSCALL::MQ_GETSETATTR:
        return SysCallId::MQ_GETSETATTR;
      case AMD64_SYSCALL::MSGGET:
        return SysCallId::MSGGET;
      case AMD64_SYSCALL::MSGCTL:
        return SysCallId::MSGCTL;
      case AMD64_SYSCALL::MSGRCV:
        return SysCallId::MSGRCV;
      case AMD64_SYSCALL::MSGSND:
        return SysCallId::MSGSND;
      case AMD64_SYSCALL::SEMGET:
        return SysCallId::SEMGET;
      case AMD64_SYSCALL::SEMCTL:
        return SysCallId::SEMCTL;
      case AMD64_SYSCALL::SEMTIMEDOP:
        return SysCallId::SEMTIMEDOP;
      case AMD64_SYSCALL::SEMOP:
        return SysCallId::SEMOP;
      case AMD64_SYSCALL::SHMGET:
        return SysCallId::SHMGET;
      case AMD64_SYSCALL::SHMCTL:
        return SysCallId::SHMCTL;
      case AMD64_SYSCALL::SHMAT:
        return SysCallId::SHMAT;
      case AMD64_SYSCALL::SHMDT:
        return SysCallId::SHMDT;
      case AMD64_SYSCALL::SOCKET:
        return SysCallId::SOCKET;
      case AMD64_SYSCALL::SOCKETPAIR:
        return SysCallId::SOCKETPAIR;
      case AMD64_SYSCALL::BIND:
        return SysCallId::BIND;
      case AMD64_SYSCALL::LISTEN:
        return SysCallId::LISTEN;
      case AMD64_SYSCALL::ACCEPT:
        return SysCallId::ACCEPT;
      case AMD64_SYSCALL::CONNECT:
        return SysCallId::CONNECT;
      case AMD64_SYSCALL::GETSOCKNAME:
        return SysCallId::GETSOCKNAME;
      case AMD64_SYSCALL::GETPEERNAME:
        return SysCallId::GETPEERNAME;
      case AMD64_SYSCALL::SENDTO:
        return SysCallId::SENDTO;
      case AMD64_SYSCALL::RECVFROM:
        return SysCallId::RECVFROM;
      case AMD64_SYSCALL::SETSOCKOPT:
        return SysCallId::SETSOCKOPT;
      case AMD64_SYSCALL::GETSOCKOPT:
        return SysCallId::GETSOCKOPT;
      case AMD64_SYSCALL::SHUTDOWN:
        return SysCallId::SHUTDOWN;
      case AMD64_SYSCALL::SENDMSG:
        return SysCallId::SENDMSG;
      case AMD64_SYSCALL::RECVMSG:
        return SysCallId::RECVMSG;
      case AMD64_SYSCALL::READAHEAD:
        return SysCallId::READAHEAD;
      case AMD64_SYSCALL::BRK:
        return SysCallId::BRK;
      case AMD64_SYSCALL::MUNMAP:
        return SysCallId::MUNMAP;
      case AMD64_SYSCALL::MREMAP:
        return SysCallId::MREMAP;
      case AMD64_SYSCALL::ADD_KEY:
        return SysCallId::ADD_KEY;
      case AMD64_SYSCALL::REQUEST_KEY:
        return SysCallId::REQUEST_KEY;
      case AMD64_SYSCALL::KEYCTL:
        return SysCallId::KEYCTL;
      case AMD64_SYSCALL::CLONE:
        return SysCallId::CLONE;
      case AMD64_SYSCALL::EXECVE:
        return SysCallId::EXECVE;
      case AMD64_SYSCALL::MMAP:
        return SysCallId::MMAP2;
      case AMD64_SYSCALL::FADVISE64:
        return SysCallId::FADVISE64;
      case AMD64_SYSCALL::SWAPON:
        return SysCallId::SWAPON;
      case AMD64_SYSCALL::SWAPOFF:
        return SysCallId::SWAPOFF;
      case AMD64_SYSCALL::MPROTECT:
        return SysCallId::MPROTECT;
      case AMD64_SYSCALL::MSYNC:
        return SysCallId::MSYNC;
      case AMD64_SYSCALL::MLOCK:
        return SysCallId::MLOCK;
      case AMD64_SYSCALL::MUNLOCK:
        return SysCallId::MUNLOCK;
      case AMD64_SYSCALL::MLOCKALL:
        return SysCallId::MLOCKALL;
      case AMD64_SYSCALL::MUNLOCKALL:
        return SysCallId::MUNLOCKALL;
      case AMD64_SYSCALL::MINCORE:
        return SysCallId::MINCORE;
      case AMD64_SYSCALL::MADVISE:
        return SysCallId::MADVISE;
      case AMD64_SYSCALL::REMAP_FILE_PAGES:
        return SysCallId::REMAP_FILE_PAGES;
      case AMD64_SYSCALL::MBIND:
        return SysCallId::MBIND;
      case AMD64_SYSCALL::GET_MEMPOLICY:
        return SysCallId::GET_MEMPOLICY;
      case AMD64_SYSCALL::SET_MEMPOLICY:
        return SysCallId::SET_MEMPOLICY;
      case AMD64_SYSCALL::MIGRATE_PAGES:
        return SysCallId::MIGRATE_PAGES;
      case AMD64_SYSCALL::MOVE_PAGES:
        return SysCallId::MOVE_PAGES;
      case AMD64_SYSCALL::RT_TGSIGQUEUEINFO:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::PERF_EVENT_OPEN:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::ACCEPT4:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::RECVMMSG:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::WAIT4:
        return SysCallId::WAIT4;
      case AMD64_SYSCALL::PRLIMIT64:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::FANOTIFY_INIT:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::FANOTIFY_MARK:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::NAME_TO_HANDLE_AT:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::OPEN_BY_HANDLE_AT:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::CLOCK_ADJTIME:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SYNCFS:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SETNS:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SENDMMSG:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::PROCESS_VM_READV:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::PROCESS_VM_WRITEV:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::KCMP:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::FINIT_MODULE:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SCHED_SETATTR:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::SCHED_GETATTR:
        return SysCallId::NO_SYSCALL;
      case AMD64_SYSCALL::GETRANDOM:
        return SysCallId::GETRANDOM;
    default:
      return SysCallId::NO_SYSCALL;
    }
}
