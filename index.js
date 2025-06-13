const profile = {
  defaultAction: "SCMP_ACT_ERRNO",
  syscalls: [
    {
      name: "accept",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "accept4",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "access",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "alarm",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "arch_prctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "bind",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "brk",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "capget",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "capset",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "chdir",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "chmod",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "chown",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "chown32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "chroot",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "clock_getres",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "clock_gettime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "clock_nanosleep",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "clone",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "close",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "connect",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "creat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "dup",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "dup2",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "dup3",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_create",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_create1",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_ctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_ctl_old",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_pwait",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_wait",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "epoll_wait_old",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "eventfd",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "eventfd2",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "execve",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "execveat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "exit",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "exit_group",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "faccessat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fadvise64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fadvise64_64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fallocate",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fanotify_init",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fanotify_mark",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchdir",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchmod",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchmodat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchown",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchown32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fchownat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fcntl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fcntl64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fdatasync",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fgetxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "flistxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "flock",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fork",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fremovexattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fsetxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fstat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fstat64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fstatat64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fstatfs",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fstatfs64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "fsync",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ftruncate",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ftruncate64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "futex",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "futimesat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getcpu",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getcwd",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getdents",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getdents64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getegid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getegid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "geteuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "geteuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getgid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getgroups",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getgroups32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getitimer",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getpeername",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getpgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getpgrp",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getpid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getppid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getpriority",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getrandom",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getresgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getresgid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getresuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getresuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getrlimit",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "get_robust_list",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getrusage",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getsid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getsockname",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getsockopt",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "get_thread_area",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "gettid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "gettimeofday",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "getxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "inotify_add_watch",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "inotify_init",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "inotify_init1",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "inotify_rm_watch",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "io_cancel",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ioctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "io_destroy",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "io_getevents",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ioprio_get",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ioprio_set",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "io_setup",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "io_submit",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "kill",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lchown",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lchown32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lgetxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "link",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "linkat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "listen",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "listxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "llistxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "_llseek",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lremovexattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lseek",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lsetxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lstat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "lstat64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "madvise",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "memfd_create",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mincore",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mkdir",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mkdirat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mknod",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mknodat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mlock",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mlockall",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mmap",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mmap2",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mprotect",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_getsetattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_notify",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_open",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_timedreceive",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_timedsend",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mq_unlink",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "mremap",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "msgctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "msgget",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "msgrcv",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "msgsnd",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "msync",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "munlock",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "munlockall",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "munmap",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "name_to_handle_at",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "nanosleep",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "newfstatat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "_newselect",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "open",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "open_by_handle_at",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "openat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pause",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pipe",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pipe2",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "poll",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ppoll",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "prctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pread64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "preadv",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "prlimit64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pselect6",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pwrite64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "pwritev",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "read",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "readahead",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "readlink",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "readlinkat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "readv",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "recvfrom",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "recvmmsg",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "recvmsg",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "remap_file_pages",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "removexattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rename",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "renameat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "renameat2",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rmdir",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigaction",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigpending",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigprocmask",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigqueueinfo",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigreturn",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigsuspend",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_sigtimedwait",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "rt_tgsigqueueinfo",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_getaffinity",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_getattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_getparam",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_get_priority_max",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_get_priority_min",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_getscheduler",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_rr_get_interval",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_setaffinity",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_setattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_setparam",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_setscheduler",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sched_yield",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "seccomp",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "select",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "semctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "semget",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "semop",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "semtimedop",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sendfile",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sendfile64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sendmmsg",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sendmsg",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sendto",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setdomainname",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setfsgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setfsgid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setfsuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setfsuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setgid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setgroups",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setgroups32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sethostname",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setitimer",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setns",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setpgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setpriority",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setregid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setregid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setresgid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setresgid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setresuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setresuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setreuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setreuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setrlimit",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "set_robust_list",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setsid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setsockopt",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "set_thread_area",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "set_tid_address",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setuid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setuid32",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "setxattr",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "shmat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "shmctl",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "shmdt",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "shmget",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "shutdown",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sigaltstack",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "signalfd",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "signalfd4",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "socket",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "socketpair",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "splice",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "stat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "stat64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "statfs",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "statfs64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "symlink",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "symlinkat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sync",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sync_file_range",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "syncfs",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "sysinfo",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "syslog",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "tee",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "tgkill",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "time",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timer_create",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timer_delete",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timerfd_create",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timerfd_gettime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timerfd_settime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timer_getoverrun",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timer_gettime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "timer_settime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "times",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "tkill",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "truncate",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "truncate64",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "ugetrlimit",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "umask",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "uname",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "unlink",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "unlinkat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "unshare",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "utime",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "utimensat",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "utimes",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "vfork",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "vhangup",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "vmsplice",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "wait4",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "waitid",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "write",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
    {
      name: "writev",
      action: "SCMP_ACT_ALLOW",
      args: null,
    },
  ],
};
const express = require("express");
const Docker = require("dockerode");
const portscanner = require("portscanner");
const axios = require("axios");

const docker = new Docker({});
const app = express();
app.use(express.json());

// Helper: generate container name
const getContainerName = (id) => `scrape-${id}`;

// Helper: build environment array
const buildEnv = (credentials, taskId = "manual") => [
  "REDIS_SERVICE=redis",
  `MYTASKID=${taskId}`,
  `TIEMCHUNG_USERNAME=${credentials.username}`,
  `TIEMCHUNG_PASSWORD=${credentials.password}`,
];
async function pullIfNeeded(imageName) {
  try {
    // Try to inspect image
    await docker.getImage(imageName).inspect();
    console.log(`✅ Image ${imageName} already exists`);
  } catch (err) {
    if (err.statusCode === 404) {
      console.log(`🔄 Pulling image ${imageName}...`);
      await new Promise((resolve, reject) => {
        docker.pull(imageName, (err, stream) => {
          if (err) return reject(err);
          docker.modem.followProgress(stream, resolve, (event) => {
            process.stdout.write(
              `  → ${event.status || ""} ${event.id || ""}\r`
            );
          });
        });
      });
      console.log(`✅ Image ${imageName} pulled`);
    } else {
      throw err;
    }
  }
}

// Create container (after pull)
async function createContainerSafe(opts) {
  const image = opts.Image;
  await pullIfNeeded(image);
  return await docker.createContainer(opts);
}
// Endpoint: create/init container
app.post("/containers", async (req, res) => {
  const { id, credentials, image } = req.body;

  if (!id || !credentials?.username || !credentials?.password) {
    return res.status(400).json({ error: "Missing id or credentials" });
  }

  const containerName = getContainerName(id);
  const container = docker.getContainer(containerName);
  let message = "";
  if (container) {
    await container.stop();
    await container.remove();
    message = "Đã khởi tạo lại!";
  }

  try {
    const container = await createContainerSafe({
      name: containerName,
      Image: image,
      Env: buildEnv(credentials),
      HostConfig: {
        SecurityOpt: [`seccomp=${JSON.stringify(profile)}`],
        RestartPolicy: { Name: "always" },
        // PortBindings: {
        //   "1306/tcp": [{ HostPort: "3001" }],
        // },
      },
      ExposedPorts: {
        "1306/tcp": {},
      },
      NetworkingConfig: {
        EndpointsConfig: {
          "vncdc-duplicator_web": {
            Aliases: [containerName],
            // Optional: set IP or aliases
            // IPAMConfig: { IPv4Address: "172.20.0.10" },
            // Aliases: ["my-container-alias"]
          },
        },
      },
    });

    await container.start();
    return res.json({
      message: `Container ${containerName} created and started.`,
      data: {
        message: message,
      },
    });
  } catch (error) {
    let message = error.message;
    if (message?.includes("is already in use by container")) {
      message = "Dịch vụ này đã tồn tại!";
      return res.status(400).json({ error: message });
    }
    return res.status(500).json({ error: message });
  }
});

// Endpoint: delete a container by id
app.delete("/containers/:id", async (req, res) => {
  const containerName = getContainerName(req.params.id);
  try {
    const container = docker.getContainer(containerName);
    await container.stop();
    await container.remove();
    return res.json({ message: `Container ${containerName} deleted.` });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// Endpoint: check available port in a range
app.get("/check-port-range", async (req, res) => {
  const startPort = parseInt(req.query.start) || 3000;
  const endPort = parseInt(req.query.end) || 3100;

  try {
    const port = await portscanner.findAPortNotInUse(startPort, endPort);
    return res.json({ availablePort: port });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});
app.use("/", async (req, res) => {
  const id = req.header("X-ID");

  if (!id) {
    return res.status(400).send("Missing X-ID header");
  }

  const targetHost = `http://${getContainerName(id)}:1306`;
  const targetUrl = new URL(req.originalUrl, targetHost);

  try {
    const axiosConfig = {
      method: req.method?.toLowerCase(),
      url: targetUrl.href,
      headers: {
        ...req.headers,
      },
      data: req.body,
      //   responseType: "stream",
    };

    const { data } = await axios(axiosConfig);
    // console.log(req.method);

    // const { data } = await axios({
    //   method: "get",
    //   url: `http://scrape-67bdcadacd2e857e4981d16c:1306/search?patientId=107150720250052`,
    // });

    res.status(200).json(data);
  } catch (err) {
    console.error(`Proxy error to ${targetHost}:`, err.message);
    res.status(502).send({ message: "Bad Gateway" });
  }
});

// Start server
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`API server running at http://localhost:${PORT}`);
});
