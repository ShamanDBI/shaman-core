#include "syscall.hpp"

std::string SysCallId::getString() const {
  switch (m_syscall_value) {
    case SysCallId::NO_SYSCALL:
      return "NO_SYSCALL";
    case SysCallId::RESTART_SYSCALL:
      return "RESTART_SYSCALL";
    case SysCallId::EXIT:
      return "EXIT";
    case SysCallId::FORK:
      return "FORK";
    case SysCallId::READ:
      return "READ";
    case SysCallId::WRITE:
      return "WRITE";
    case SysCallId::OPEN:
      return "OPEN";
    case SysCallId::CLOSE:
      return "CLOSE";
    case SysCallId::WAITPID:
      return "WAITPID";
    case SysCallId::CREAT:
      return "CREAT";
    case SysCallId::LINK:
      return "LINK";
    case SysCallId::UNLINK:
      return "UNLINK";
    case SysCallId::EXECVE:
      return "EXECVE";
    case SysCallId::CHDIR:
      return "CHDIR";
    case SysCallId::TIME:
      return "TIME";
    case SysCallId::MKNOD:
      return "MKNOD";
    case SysCallId::CHMOD:
      return "CHMOD";
    case SysCallId::LCHOWN16:
      return "LCHOWN16";
    case SysCallId::NI_SYSCALL17:
      return "NI_SYSCALL17";
    case SysCallId::STAT:
      return "STAT";
    case SysCallId::LSEEK:
      return "LSEEK";
    case SysCallId::GETPID:
      return "GETPID";
    case SysCallId::MOUNT:
      return "MOUNT";
    case SysCallId::OLDUMOUNT:
      return "OLDUMOUNT";
    case SysCallId::SETUID16:
      return "SETUID16";
    case SysCallId::GETUID16:
      return "GETUID16";
    case SysCallId::STIME:
      return "STIME";
    case SysCallId::PTRACE:
      return "PTRACE";
    case SysCallId::ALARM:
      return "ALARM";
    case SysCallId::FSTAT:
      return "FSTAT";
    case SysCallId::PAUSE:
      return "PAUSE";
    case SysCallId::UTIME:
      return "UTIME";
    case SysCallId::NI_SYSCALL31:
      return "NI_SYSCALL31";
    case SysCallId::NI_SYSCALL32:
      return "NI_SYSCALL32";
    case SysCallId::ACCESS:
      return "ACCESS";
    case SysCallId::NICE:
      return "NICE";
    case SysCallId::NI_SYSCALL35:
      return "NI_SYSCALL35";
    case SysCallId::SYNC:
      return "SYNC";
    case SysCallId::KILL:
      return "KILL";
    case SysCallId::RENAME:
      return "RENAME";
    case SysCallId::MKDIR:
      return "MKDIR";
    case SysCallId::RMDIR:
      return "RMDIR";
    case SysCallId::DUP:
      return "DUP";
    case SysCallId::PIPE:
      return "PIPE";
    case SysCallId::TIMES:
      return "TIMES";
    case SysCallId::NI_SYSCALL44:
      return "NI_SYSCALL44";
    case SysCallId::BRK:
      return "BRK";
    case SysCallId::SETGID16:
      return "SETGID16";
    case SysCallId::GETGID16:
      return "GETGID16";
    case SysCallId::SIGNAL:
      return "SIGNAL";
    case SysCallId::GETEUID16:
      return "GETEUID16";
    case SysCallId::GETEGID16:
      return "GETEGID16";
    case SysCallId::ACCT:
      return "ACCT";
    case SysCallId::UMOUNT:
      return "UMOUNT";
    case SysCallId::NI_SYSCALL53:
      return "NI_SYSCALL53";
    case SysCallId::IOCTL:
      return "IOCTL";
    case SysCallId::FCNTL:
      return "FCNTL";
    case SysCallId::NI_SYSCALL56:
      return "NI_SYSCALL56";
    case SysCallId::SETPGID:
      return "SETPGID";
    case SysCallId::NI_SYSCALL58:
      return "NI_SYSCALL58";
    case SysCallId::OLDUNAME:
      return "OLDUNAME";
    case SysCallId::UMASK:
      return "UMASK";
    case SysCallId::CHROOT:
      return "CHROOT";
    case SysCallId::USTAT:
      return "USTAT";
    case SysCallId::DUP2:
      return "DUP2";
    case SysCallId::GETPPID:
      return "GETPPID";
    case SysCallId::GETPGRP:
      return "GETPGRP";
    case SysCallId::SETSID:
      return "SETSID";
    case SysCallId::SIGACTION:
      return "SIGACTION";
    case SysCallId::SGETMASK:
      return "SGETMASK";
    case SysCallId::SSETMASK:
      return "SSETMASK";
    case SysCallId::SETREUID16:
      return "SETREUID16";
    case SysCallId::SETREGID16:
      return "SETREGID16";
    case SysCallId::SIGSUSPEND:
      return "SIGSUSPEND";
    case SysCallId::SIGPENDING:
      return "SIGPENDING";
    case SysCallId::SETHOSTNAME:
      return "SETHOSTNAME";
    case SysCallId::SETRLIMIT:
      return "SETRLIMIT";
    case SysCallId::OLD_GETRLIMIT:
      return "OLD_GETRLIMIT";
    case SysCallId::GETRUSAGE:
      return "GETRUSAGE";
    case SysCallId::GETTIMEOFDAY:
      return "GETTIMEOFDAY";
    case SysCallId::SETTIMEOFDAY:
      return "SETTIMEOFDAY";
    case SysCallId::GETGROUPS16:
      return "GETGROUPS16";
    case SysCallId::SETGROUPS16:
      return "SETGROUPS16";
    case SysCallId::OLD_SELECT:
      return "OLD_SELECT";
    case SysCallId::SYMLINK:
      return "SYMLINK";
    case SysCallId::LSTAT:
      return "LSTAT";
    case SysCallId::READLINK:
      return "READLINK";
    case SysCallId::USELIB:
      return "USELIB";
    case SysCallId::SWAPON:
      return "SWAPON";
    case SysCallId::REBOOT:
      return "REBOOT";
    case SysCallId::OLD_READDIR:
      return "OLD_READDIR";
    case SysCallId::OLD_MMAP:
      return "OLD_MMAP";
    case SysCallId::MUNMAP:
      return "MUNMAP";
    case SysCallId::TRUNCATE:
      return "TRUNCATE";
    case SysCallId::FTRUNCATE:
      return "FTRUNCATE";
    case SysCallId::FCHMOD:
      return "FCHMOD";
    case SysCallId::FCHOWN16:
      return "FCHOWN16";
    case SysCallId::GETPRIORITY:
      return "GETPRIORITY";
    case SysCallId::SETPRIORITY:
      return "SETPRIORITY";
    case SysCallId::NI_SYSCALL98:
      return "NI_SYSCALL98";
    case SysCallId::STATFS:
      return "STATFS";
    case SysCallId::FSTATFS:
      return "FSTATFS";
    case SysCallId::IOPERM:
      return "IOPERM";
    case SysCallId::SOCKETCALL:
      return "SOCKETCALL";
    case SysCallId::SYSLOG:
      return "SYSLOG";
    case SysCallId::SETITIMER:
      return "SETITIMER";
    case SysCallId::GETITIMER:
      return "GETITIMER";
    case SysCallId::NEWSTAT:
      return "NEWSTAT";
    case SysCallId::NEWLSTAT:
      return "NEWLSTAT";
    case SysCallId::NEWFSTAT:
      return "NEWFSTAT";
    case SysCallId::UNAME:
      return "UNAME";
    case SysCallId::IOPL:
      return "IOPL";
    case SysCallId::VHANGUP:
      return "VHANGUP";
    case SysCallId::NI_SYSCALL112:
      return "NI_SYSCALL112";
    case SysCallId::VM86OLD:
      return "VM86OLD";
    case SysCallId::WAIT4:
      return "WAIT4";
    case SysCallId::SWAPOFF:
      return "SWAPOFF";
    case SysCallId::SYSINFO:
      return "SYSINFO";
    case SysCallId::IPC:
      return "IPC";
    case SysCallId::FSYNC:
      return "FSYNC";
    case SysCallId::SIGRETURN:
      return "SIGRETURN";
    case SysCallId::CLONE:
      return "CLONE";
    case SysCallId::SETDOMAINNAME:
      return "SETDOMAINNAME";
    case SysCallId::NEWUNAME:
      return "NEWUNAME";
    case SysCallId::MODIFY_LDT:
      return "MODIFY_LDT";
    case SysCallId::ADJTIMEX:
      return "ADJTIMEX";
    case SysCallId::MPROTECT:
      return "MPROTECT";
    case SysCallId::SIGPROCMASK:
      return "SIGPROCMASK";
    case SysCallId::NI_SYSCALL127:
      return "NI_SYSCALL127";
    case SysCallId::INIT_MODULE:
      return "INIT_MODULE";
    case SysCallId::DELETE_MODULE:
      return "DELETE_MODULE";
    case SysCallId::NI_SYSCALL130:
      return "NI_SYSCALL130";
    case SysCallId::QUOTACTL:
      return "QUOTACTL";
    case SysCallId::GETPGID:
      return "GETPGID";
    case SysCallId::FCHDIR:
      return "FCHDIR";
    case SysCallId::BDFLUSH:
      return "BDFLUSH";
    case SysCallId::SYSFS:
      return "SYSFS";
    case SysCallId::PERSONALITY:
      return "PERSONALITY";
    case SysCallId::NI_SYSCALL137:
      return "NI_SYSCALL137";
    case SysCallId::SETFSUID16:
      return "SETFSUID16";
    case SysCallId::SETFSGID16:
      return "SETFSGID16";
    case SysCallId::LLSEEK:
      return "LLSEEK";
    case SysCallId::GETDENTS:
      return "GETDENTS";
    case SysCallId::SELECT:
      return "SELECT";
    case SysCallId::FLOCK:
      return "FLOCK";
    case SysCallId::MSYNC:
      return "MSYNC";
    case SysCallId::READV:
      return "READV";
    case SysCallId::WRITEV:
      return "WRITEV";
    case SysCallId::GETSID:
      return "GETSID";
    case SysCallId::FDATASYNC:
      return "FDATASYNC";
    case SysCallId::SYSCTL:
      return "SYSCTL";
    case SysCallId::MLOCK:
      return "MLOCK";
    case SysCallId::MUNLOCK:
      return "MUNLOCK";
    case SysCallId::MLOCKALL:
      return "MLOCKALL";
    case SysCallId::MUNLOCKALL:
      return "MUNLOCKALL";
    case SysCallId::SCHED_SETPARAM:
      return "SCHED_SETPARAM";
    case SysCallId::SCHED_GETPARAM:
      return "SCHED_GETPARAM";
    case SysCallId::SCHED_SETSCHEDULER:
      return "SCHED_SETSCHEDULER";
    case SysCallId::SCHED_GETSCHEDULER:
      return "SCHED_GETSCHEDULER";
    case SysCallId::SCHED_YIELD:
      return "SCHED_YIELD";
    case SysCallId::SCHED_GET_PRIORITY_MAX:
      return "SCHED_GET_PRIORITY_MAX";
    case SysCallId::SCHED_GET_PRIORITY_MIN:
      return "SCHED_GET_PRIORITY_MIN";
    case SysCallId::SCHED_RR_GET_INTERVAL:
      return "SCHED_RR_GET_INTERVAL";
    case SysCallId::NANOSLEEP:
      return "NANOSLEEP";
    case SysCallId::MREMAP:
      return "MREMAP";
    case SysCallId::SETRESUID16:
      return "SETRESUID16";
    case SysCallId::GETRESUID16:
      return "GETRESUID16";
    case SysCallId::VM86:
      return "VM86";
    case SysCallId::NI_SYSCALL167:
      return "NI_SYSCALL167";
    case SysCallId::POLL:
      return "POLL";
    case SysCallId::NFSSERVCTL:
      return "NFSSERVCTL";
    case SysCallId::SETRESGID16:
      return "SETRESGID16";
    case SysCallId::GETRESGID16:
      return "GETRESGID16";
    case SysCallId::PRCTL:
      return "PRCTL";
    case SysCallId::RT_SIGRETURN:
      return "RT_SIGRETURN";
    case SysCallId::RT_SIGACTION:
      return "RT_SIGACTION";
    case SysCallId::RT_SIGPROCMASK:
      return "RT_SIGPROCMASK";
    case SysCallId::RT_SIGPENDING:
      return "RT_SIGPENDING";
    case SysCallId::RT_SIGTIMEDWAIT:
      return "RT_SIGTIMEDWAIT";
    case SysCallId::RT_SIGQUEUEINFO:
      return "RT_SIGQUEUEINFO";
    case SysCallId::RT_SIGSUSPEND:
      return "RT_SIGSUSPEND";
    case SysCallId::PREAD64:
      return "PREAD64";
    case SysCallId::PWRITE64:
      return "PWRITE64";
    case SysCallId::CHOWN16:
      return "CHOWN16";
    case SysCallId::GETCWD:
      return "GETCWD";
    case SysCallId::CAPGET:
      return "CAPGET";
    case SysCallId::CAPSET:
      return "CAPSET";
    case SysCallId::SIGALTSTACK:
      return "SIGALTSTACK";
    case SysCallId::SENDFILE:
      return "SENDFILE";
    case SysCallId::NI_SYSCALL188:
      return "NI_SYSCALL188";
    case SysCallId::NI_SYSCALL189:
      return "NI_SYSCALL189";
    case SysCallId::VFORK:
      return "VFORK";
    case SysCallId::GETRLIMIT:
      return "GETRLIMIT";
    case SysCallId::MMAP2:
      return "MMAP2";
    case SysCallId::TRUNCATE64:
      return "TRUNCATE64";
    case SysCallId::FTRUNCATE64:
      return "FTRUNCATE64";
    case SysCallId::STAT64:
      return "STAT64";
    case SysCallId::LSTAT64:
      return "LSTAT64";
    case SysCallId::FSTAT64:
      return "FSTAT64";
    case SysCallId::LCHOWN:
      return "LCHOWN";
    case SysCallId::GETUID:
      return "GETUID";
    case SysCallId::GETGID:
      return "GETGID";
    case SysCallId::GETEUID:
      return "GETEUID";
    case SysCallId::GETEGID:
      return "GETEGID";
    case SysCallId::SETREUID:
      return "SETREUID";
    case SysCallId::SETREGID:
      return "SETREGID";
    case SysCallId::GETGROUPS:
      return "GETGROUPS";
    case SysCallId::SETGROUPS:
      return "SETGROUPS";
    case SysCallId::FCHOWN:
      return "FCHOWN";
    case SysCallId::SETRESUID:
      return "SETRESUID";
    case SysCallId::GETRESUID:
      return "GETRESUID";
    case SysCallId::SETRESGID:
      return "SETRESGID";
    case SysCallId::GETRESGID:
      return "GETRESGID";
    case SysCallId::CHOWN:
      return "CHOWN";
    case SysCallId::SETUID:
      return "SETUID";
    case SysCallId::SETGID:
      return "SETGID";
    case SysCallId::SETFSUID:
      return "SETFSUID";
    case SysCallId::SETFSGID:
      return "SETFSGID";
    case SysCallId::PIVOT_ROOT:
      return "PIVOT_ROOT";
    case SysCallId::MINCORE:
      return "MINCORE";
    case SysCallId::MADVISE:
      return "MADVISE";
    case SysCallId::GETDENTS64:
      return "GETDENTS64";
    case SysCallId::FCNTL64:
      return "FCNTL64";
    case SysCallId::NI_SYSCALL222:
      return "NI_SYSCALL222";
    case SysCallId::NI_SYSCALL223:
      return "NI_SYSCALL223";
    case SysCallId::GETTID:
      return "GETTID";
    case SysCallId::READAHEAD:
      return "READAHEAD";
    case SysCallId::SETXATTR:
      return "SETXATTR";
    case SysCallId::LSETXATTR:
      return "LSETXATTR";
    case SysCallId::FSETXATTR:
      return "FSETXATTR";
    case SysCallId::GETXATTR:
      return "GETXATTR";
    case SysCallId::LGETXATTR:
      return "LGETXATTR";
    case SysCallId::FGETXATTR:
      return "FGETXATTR";
    case SysCallId::LISTXATTR:
      return "LISTXATTR";
    case SysCallId::LLISTXATTR:
      return "LLISTXATTR";
    case SysCallId::FLISTXATTR:
      return "FLISTXATTR";
    case SysCallId::REMOVEXATTR:
      return "REMOVEXATTR";
    case SysCallId::LREMOVEXATTR:
      return "LREMOVEXATTR";
    case SysCallId::FREMOVEXATTR:
      return "FREMOVEXATTR";
    case SysCallId::TKILL:
      return "TKILL";
    case SysCallId::SENDFILE64:
      return "SENDFILE64";
    case SysCallId::FUTEX:
      return "FUTEX";
    case SysCallId::SCHED_SETAFFINITY:
      return "SCHED_SETAFFINITY";
    case SysCallId::SCHED_GETAFFINITY:
      return "SCHED_GETAFFINITY";
    case SysCallId::SET_THREAD_AREA:
      return "SET_THREAD_AREA";
    case SysCallId::GET_THREAD_AREA:
      return "GET_THREAD_AREA";
    case SysCallId::IO_SETUP:
      return "IO_SETUP";
    case SysCallId::IO_DESTROY:
      return "IO_DESTROY";
    case SysCallId::IO_GETEVENTS:
      return "IO_GETEVENTS";
    case SysCallId::IO_SUBMIT:
      return "IO_SUBMIT";
    case SysCallId::IO_CANCEL:
      return "IO_CANCEL";
    case SysCallId::FADVISE64:
      return "FADVISE64";
    case SysCallId::NI_SYSCALL251:
      return "NI_SYSCALL251";
    case SysCallId::EXIT_GROUP:
      return "EXIT_GROUP";
    case SysCallId::LOOKUP_DCOOKIE:
      return "LOOKUP_DCOOKIE";
    case SysCallId::EPOLL_CREATE:
      return "EPOLL_CREATE";
    case SysCallId::EPOLL_CTL:
      return "EPOLL_CTL";
    case SysCallId::EPOLL_WAIT:
      return "EPOLL_WAIT";
    case SysCallId::REMAP_FILE_PAGES:
      return "REMAP_FILE_PAGES";
    case SysCallId::SET_TID_ADDRESS:
      return "SET_TID_ADDRESS";
    case SysCallId::TIMER_CREATE:
      return "TIMER_CREATE";
    case SysCallId::TIMER_SETTIME:
      return "TIMER_SETTIME";
    case SysCallId::TIMER_GETTIME:
      return "TIMER_GETTIME";
    case SysCallId::TIMER_GETOVERRUN:
      return "TIMER_GETOVERRUN";
    case SysCallId::TIMER_DELETE:
      return "TIMER_DELETE";
    case SysCallId::CLOCK_SETTIME:
      return "CLOCK_SETTIME";
    case SysCallId::CLOCK_GETTIME:
      return "CLOCK_GETTIME";
    case SysCallId::CLOCK_GETRES:
      return "CLOCK_GETRES";
    case SysCallId::CLOCK_NANOSLEEP:
      return "CLOCK_NANOSLEEP";
    case SysCallId::STATFS64:
      return "STATFS64";
    case SysCallId::FSTATFS64:
      return "FSTATFS64";
    case SysCallId::TGKILL:
      return "TGKILL";
    case SysCallId::UTIMES:
      return "UTIMES";
    case SysCallId::FADVISE64_64:
      return "FADVISE64_64";
    case SysCallId::NI_SYSCALL273:
      return "NI_SYSCALL273";
    case SysCallId::MBIND:
      return "MBIND";
    case SysCallId::GET_MEMPOLICY:
      return "GET_MEMPOLICY";
    case SysCallId::SET_MEMPOLICY:
      return "SET_MEMPOLICY";
    case SysCallId::MQ_OPEN:
      return "MQ_OPEN";
    case SysCallId::MQ_UNLINK:
      return "MQ_UNLINK";
    case SysCallId::MQ_TIMEDSEND:
      return "MQ_TIMEDSEND";
    case SysCallId::MQ_TIMEDRECEIVE:
      return "MQ_TIMEDRECEIVE";
    case SysCallId::MQ_NOTIFY:
      return "MQ_NOTIFY";
    case SysCallId::MQ_GETSETATTR:
      return "MQ_GETSETATTR";
    case SysCallId::KEXEC_LOAD:
      return "KEXEC_LOAD";
    case SysCallId::WAITID:
      return "WAITID";
    case SysCallId::NI_SYSCALL285:
      return "NI_SYSCALL285";
    case SysCallId::ADD_KEY:
      return "ADD_KEY";
    case SysCallId::REQUEST_KEY:
      return "REQUEST_KEY";
    case SysCallId::KEYCTL:
      return "KEYCTL";
    case SysCallId::IOPRIO_SET:
      return "IOPRIO_SET";
    case SysCallId::IOPRIO_GET:
      return "IOPRIO_GET";
    case SysCallId::INOTIFY_INIT:
      return "INOTIFY_INIT";
    case SysCallId::INOTIFY_ADD_WATCH:
      return "INOTIFY_ADD_WATCH";
    case SysCallId::INOTIFY_RM_WATCH:
      return "INOTIFY_RM_WATCH";
    case SysCallId::MIGRATE_PAGES:
      return "MIGRATE_PAGES";
    case SysCallId::OPENAT:
      return "OPENAT";
    case SysCallId::MKDIRAT:
      return "MKDIRAT";
    case SysCallId::MKNODAT:
      return "MKNODAT";
    case SysCallId::FCHOWNAT:
      return "FCHOWNAT";
    case SysCallId::FUTIMESAT:
      return "FUTIMESAT";
    case SysCallId::FSTATAT64:
      return "FSTATAT64";
    case SysCallId::UNLINKAT:
      return "UNLINKAT";
    case SysCallId::RENAMEAT:
      return "RENAMEAT";
    case SysCallId::LINKAT:
      return "LINKAT";
    case SysCallId::SYMLINKAT:
      return "SYMLINKAT";
    case SysCallId::READLINKAT:
      return "READLINKAT";
    case SysCallId::FCHMODAT:
      return "FCHMODAT";
    case SysCallId::FACCESSAT:
      return "FACCESSAT";
    case SysCallId::PSELECT6:
      return "PSELECT6";
    case SysCallId::PPOLL:
      return "PPOLL";
    case SysCallId::UNSHARE:
      return "UNSHARE";
    case SysCallId::SET_ROBUST_LIST:
      return "SET_ROBUST_LIST";
    case SysCallId::GET_ROBUST_LIST:
      return "GET_ROBUST_LIST";
    case SysCallId::SPLICE:
      return "SPLICE";
    case SysCallId::SYNC_FILE_RANGE:
      return "SYNC_FILE_RANGE";
    case SysCallId::TEE:
      return "TEE";
    case SysCallId::VMSPLICE:
      return "VMSPLICE";
    case SysCallId::MOVE_PAGES:
      return "MOVE_PAGES";
    case SysCallId::GETCPU:
      return "GETCPU";
    case SysCallId::EPOLL_PWAIT:
      return "EPOLL_PWAIT";
    case SysCallId::FALLOCATE:
      return "FALLOCATE";
    case SysCallId::EVENTFD2:
      return "EVENTFD2";
    case SysCallId::EPOLL_CREATE1:
      return "EPOLL_CREATE1";
    case SysCallId::DUP3:
      return "DUP3";
    case SysCallId::PIPE2:
      return "PIPE2";
    case SysCallId::INOTIFY_INIT1:
      return "INOTIFY_INIT1";
    case SysCallId::GETRANDOM:
      return "GETRANDOM";
    case SysCallId::STATX:
      return "STATX";
    case SysCallId::SOCKET:
      return "SOCKET";
    case SysCallId::CONNECT:
      return "CONNECT";
    case SysCallId::ACCEPT:
      return "ACCEPT";
    case SysCallId::SENDTO:
      return "SENDTO";
    case SysCallId::RECVFROM:
      return "RECVFROM";
    case SysCallId::SENDMSG:
      return "SENDMSG";
    case SysCallId::RECVMSG:
      return "RECVMSG";
    case SysCallId::SHUTDOWN:
      return "SHUTDOWN";
    case SysCallId::BIND:
      return "BIND";
    case SysCallId::LISTEN:
      return "LISTEN";
    case SysCallId::GETSOCKNAME:
      return "GETSOCKNAME";
    case SysCallId::GETPEERNAME:
      return "GETPEERNAME";
    case SysCallId::SOCKETPAIR:
      return "SOCKETPAIR";
    case SysCallId::SETSOCKOPT:
      return "SETSOCKOPT";
    case SysCallId::GETSOCKOPT:
      return "GETSOCKOPT";
    case SysCallId::RECV:
      return "RECV";
    case SysCallId::SHMGET:
      return "SHMGET";
    case SysCallId::SHMAT:
      return "SHMAT";
    case SysCallId::SHMCTL:
      return "SHMCTL";
    case SysCallId::SEMGET:
      return "SEMGET";
    case SysCallId::SEMOP:
      return "SEMOP";
    case SysCallId::SEMCTL:
      return "SEMCTL";
    case SysCallId::SHMDT:
      return "SHMDT";
    case SysCallId::MSGGET:
      return "MSGGET";
    case SysCallId::MSGSND:
      return "MSGSND";
    case SysCallId::MSGRCV:
      return "MSGRCV";
    case SysCallId::MSGCTL:
      return "MSGCTL";
    case SysCallId::SEMTIMEDOP:
      return "SEMTIMEDOP";
    case SysCallId::NEWFSTATAT:
      return "NEWFSTATAT";
    case SysCallId::ARCH_PRCTL:
      return "ARCH_PRCTL";
    default:
      return "UNKNOWN";
      break;
  }
}


bool SysCallId::hasValue(syscall_no aValue) {
  return aValue == m_syscall_value;
}

SysCallId::syscall_no SysCallId::getValue() const {
  return m_syscall_value;
}

bool SysCallId::operator==(const SysCallId& rhs) const {
  return m_syscall_value == rhs.m_syscall_value;
}

bool SysCallId::operator!=(const SysCallId& rhs) const {
  return !(rhs == *this);
}

std::ostream& operator<<(std::ostream& out, const SysCallId baggageType) {
  out << baggageType.getString();
  return out;
}
