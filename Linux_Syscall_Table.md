| Syscall Number | Syscall Name | Brief Description | Function Prototype |
|----------------|--------------|-------------------|--------------------|
| 0 | read | read from a file descriptor | `ssize_t read(int fd, void *buf, size_t count);` |
| 1 | write | write to a file descriptor | `ssize_t write(int fd, const void *buf, size_t count);` |
| 2 | open | open and possibly create a file | `int open(const char *pathname, int flags);` |
| 3 | close | close a file descriptor | `int close(int fd);` |
| 4 | stat | get file status | `int stat(const char *pathname, struct stat *statbuf);` |
| 5 | fstat | get file status | `int stat(const char *pathname, struct stat *statbuf);` |
| 6 | lstat | get file status | `int stat(const char *pathname, struct stat *statbuf);` |
| 7 | poll | wait for some event on a file descriptor | `int poll(struct pollfd *fds, nfds_t nfds, int timeout);` |
| 8 | lseek | reposition read/write file offset | `off_t lseek(int fd, off_t offset, int whence);` |
| 9 | mmap | map or unmap files or devices into memory | `void *mmap(void *addr, size_t length, int prot, int flags,` |
| 10 | mprotect | set protection on a region of memory | `int mprotect(void *addr, size_t len, int prot);` |
| 11 | munmap | map or unmap files or devices into memory | `void *mmap(void *addr, size_t length, int prot, int flags,` |
| 12 | brk | change data segment size | `int brk(void *addr);` |
| 13 | rt_sigaction | examine and change a signal action | `int sigaction(int signum, const struct sigaction *act,` |
| 14 | rt_sigprocmask | examine and change blocked signals | `/* Prototype for the glibc wrapper function */` |
| 15 | rt_sigreturn | return from signal handler and cleanup stack frame | `int sigreturn(...);` |
| 16 | ioctl | control device | `int ioctl(int fd, unsigned long request, ...);` |
| 17 | pread64 | read from or write to a file descriptor at a given offset | `ssize_t pread(int fd, void *buf, size_t count, off_t offset);` |
| 18 | pwrite64 | read from or write to a file descriptor at a given offset | `ssize_t pread(int fd, void *buf, size_t count, off_t offset);` |
| 19 | readv | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 20 | writev | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 21 | access | check user's permissions for a file | `int access(const char *pathname, int mode);` |
| 22 | pipe | create pipe | `/* On Alpha, IA-64, MIPS, SuperH, and SPARC/SPARC64; see NOTES */` |
| 23 | select | synchronous I/O multiplexing | `/* According to POSIX.1-2001, POSIX.1-2008 */` |
| 24 | sched_yield | yield the processor | `int sched_yield(void);` |
| 25 | mremap | remap a virtual memory address | `void *mremap(void *old_address, size_t old_size,` |
| 26 | msync | synchronize a file with a memory map | `int msync(void *addr, size_t length, int flags);` |
| 27 | mincore | determine whether pages are resident in memory | `int mincore(void *addr, size_t length, unsigned char *vec);` |
| 28 | madvise | give advice about use of memory | `int madvise(void *addr, size_t length, int advice);` |
| 29 | shmget | allocates a System V shared memory segment | `int shmget(key_t key, size_t size, int shmflg);` |
| 30 | shmat | System V shared memory operations | `void *shmat(int shmid, const void *shmaddr, int shmflg);` |
| 31 | shmctl | System V shared memory control | `int shmctl(int shmid, int cmd, struct shmid_ds *buf);` |
| 32 | dup | duplicate a file descriptor | `int dup(int oldfd);` |
| 33 | dup2 | duplicate a file descriptor | `int dup(int oldfd);` |
| 34 | pause | wait for signal | `int pause(void);` |
| 35 | nanosleep | high-resolution sleep | `int nanosleep(const struct timespec *req, struct timespec *rem);` |
| 36 | getitimer | get or set value of an interval timer | `int getitimer(int which, struct itimerval *curr_value);` |
| 37 | alarm | set an alarm clock for delivery of a signal | `unsigned int alarm(unsigned int seconds);` |
| 38 | setitimer | get or set value of an interval timer | `int getitimer(int which, struct itimerval *curr_value);` |
| 39 | getpid | get process identification | `pid_t getpid(void);` |
| 40 | sendfile | transfer data between file descriptors | `ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);` |
| 41 | socket | create an endpoint for communication | `int socket(int domain, int type, int protocol);` |
| 42 | connect | initiate a connection on a socket | `int connect(int sockfd, const struct sockaddr *addr,` |
| 43 | accept | accept a connection on a socket | `int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);` |
| 44 | sendto | send a message on a socket | `ssize_t send(int sockfd, const void *buf, size_t len, int flags);` |
| 45 | recvfrom | receive a message from a socket | `ssize_t recv(int sockfd, void *buf, size_t len, int flags);` |
| 46 | sendmsg | send a message on a socket | `ssize_t send(int sockfd, const void *buf, size_t len, int flags);` |
| 47 | recvmsg | receive a message from a socket | `ssize_t recv(int sockfd, void *buf, size_t len, int flags);` |
| 48 | shutdown | shut down part of a full-duplex connection | `int shutdown(int sockfd, int how);` |
| 49 | bind | bind a name to a socket | `int bind(int sockfd, const struct sockaddr *addr,` |
| 50 | listen | listen for connections on a socket | `int listen(int sockfd, int backlog);` |
| 51 | getsockname | get socket name | `int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);` |
| 52 | getpeername | get name of connected peer socket | `int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);` |
| 53 | socketpair | create a pair of connected sockets | `int socketpair(int domain, int type, int protocol, int sv[2]);` |
| 54 | setsockopt | get and set options on sockets | `int getsockopt(int sockfd, int level, int optname,` |
| 55 | getsockopt | get and set options on sockets | `int getsockopt(int sockfd, int level, int optname,` |
| 56 | clone | create a child process | `/* Prototype for the glibc wrapper function */` |
| 57 | fork | create a child process | `pid_t fork(void);` |
| 58 | vfork | create a child process and block parent | `pid_t vfork(void);` |
| 59 | execve | execute program | `int execve(const char *pathname, char *const argv[],` |
| 60 | exit | terminate the calling process | `void _exit(int status);` |
| 61 | wait4 | wait for process to change state, BSD style | `pid_t wait3(int *wstatus, int options,` |
| 62 | kill | send signal to a process | `int kill(pid_t pid, int sig);` |
| 63 | uname | get name and information about current kernel | `int uname(struct utsname *buf);` |
| 64 | semget | get a System V semaphore set identifier | `int semget(key_t key, int nsems, int semflg);` |
| 65 | semop | System V semaphore operations | `int semop(int semid, struct sembuf *sops, size_t nsops);` |
| 66 | semctl | System V semaphore control operations | `int semctl(int semid, int semnum, int cmd, ...);` |
| 67 | shmdt | System V shared memory operations | `void *shmat(int shmid, const void *shmaddr, int shmflg);` |
| 68 | msgget | get a System V message queue identifier | `int msgget(key_t key, int msgflg);` |
| 69 | msgsnd | System V message queue operations | `int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);` |
| 70 | msgrcv | System V message queue operations | `int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);` |
| 71 | msgctl | System V message control operations | `int msgctl(int msqid, int cmd, struct msqid_ds *buf);` |
| 72 | fcntl | manipulate file descriptor | `int fcntl(int fd, int cmd, ... /* arg */ );` |
| 73 | flock | apply or remove an advisory lock on an open file | `int flock(int fd, int operation);` |
| 74 | fsync | synchronize a file's in-core state with storage device | `int fsync(int fd);` |
| 75 | fdatasync | synchronize a file's in-core state with storage device | `int fsync(int fd);` |
| 76 | truncate | truncate a file to a specified length | `int truncate(const char *path, off_t length);` |
| 77 | ftruncate | truncate a file to a specified length | `int truncate(const char *path, off_t length);` |
| 78 | getdents | get directory entries | `int getdents(unsigned int fd, struct linux_dirent *dirp,` |
| 79 | getcwd | get current working directory | `char *getcwd(char *buf, size_t size);` |
| 80 | chdir | change working directory | `int chdir(const char *path);` |
| 81 | fchdir | change working directory | `int chdir(const char *path);` |
| 82 | rename | change the name or location of a file | `int rename(const char *oldpath, const char *newpath);` |
| 83 | mkdir | create a directory | `int mkdir(const char *pathname, mode_t mode);` |
| 84 | rmdir | delete a directory | `int rmdir(const char *pathname);` |
| 85 | creat | open and possibly create a file | `int open(const char *pathname, int flags);` |
| 86 | link | make a new name for a file | `int link(const char *oldpath, const char *newpath);` |
| 87 | unlink | delete a name and possibly the file it refers to | `int unlink(const char *pathname);` |
| 88 | symlink | make a new name for a file | `int symlink(const char *target, const char *linkpath);` |
| 89 | readlink | read value of a symbolic link | `ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);` |
| 90 | chmod | change permissions of a file | `int chmod(const char *pathname, mode_t mode);` |
| 91 | fchmod | change permissions of a file | `int chmod(const char *pathname, mode_t mode);` |
| 92 | chown | change ownership of a file | `int chown(const char *pathname, uid_t owner, gid_t group);` |
| 93 | fchown | change ownership of a file | `int chown(const char *pathname, uid_t owner, gid_t group);` |
| 94 | lchown | change ownership of a file | `int chown(const char *pathname, uid_t owner, gid_t group);` |
| 95 | umask | set file mode creation mask | `mode_t umask(mode_t mask);` |
| 96 | gettimeofday | get / set time | `int gettimeofday(struct timeval *tv, struct timezone *tz);` |
| 97 | getrlimit | get/set resource limits | `int getrlimit(int resource, struct rlimit *rlim);` |
| 98 | getrusage | get resource usage | `int getrusage(int who, struct rusage *usage);` |
| 99 | sysinfo | return system information | `int sysinfo(struct sysinfo *info);` |
| 100 | times | get process times | `clock_t times(struct tms *buf);` |
| 101 | ptrace | process trace | `long ptrace(enum __ptrace_request request, pid_t pid,` |
| 102 | getuid | get user identity | `uid_t getuid(void);` |
| 103 | syslog | read and/or clear kernel message ring buffer; set console_loglevel | `int syslog(int type, char *bufp, int len);` |
| 104 | getgid | get group identity | `gid_t getgid(void);` |
| 105 | setuid | set user identity | `int setuid(uid_t uid);` |
| 106 | setgid | set group identity | `int setgid(gid_t gid);` |
| 107 | geteuid | get user identity | `uid_t getuid(void);` |
| 108 | getegid | get group identity | `gid_t getgid(void);` |
| 109 | setpgid | set/get process group | `int setpgid(pid_t pid, pid_t pgid);` |
| 110 | getppid | get process identification | `pid_t getpid(void);` |
| 111 | getpgrp | set/get process group | `int setpgid(pid_t pid, pid_t pgid);` |
| 112 | setsid | creates a session and sets the process group ID | `pid_t setsid(void);` |
| 113 | setreuid | set real and/or effective user or group ID | `int setreuid(uid_t ruid, uid_t euid);` |
| 114 | setregid | set real and/or effective user or group ID | `int setreuid(uid_t ruid, uid_t euid);` |
| 115 | getgroups | get/set list of supplementary group IDs | `int getgroups(int size, gid_t list[]);` |
| 116 | setgroups | get/set list of supplementary group IDs | `int getgroups(int size, gid_t list[]);` |
| 117 | setresuid | set real, effective and saved user or group ID | `int setresuid(uid_t ruid, uid_t euid, uid_t suid);` |
| 118 | getresuid | get real, effective and saved user/group IDs | `int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);` |
| 119 | setresgid | set real, effective and saved user or group ID | `int setresuid(uid_t ruid, uid_t euid, uid_t suid);` |
| 120 | getresgid | get real, effective and saved user/group IDs | `int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);` |
| 121 | getpgid | set/get process group | `int setpgid(pid_t pid, pid_t pgid);` |
| 122 | setfsuid | set user identity used for filesystem checks | `int setfsuid(uid_t fsuid);` |
| 123 | setfsgid | set group identity used for filesystem checks | `int setfsgid(uid_t fsgid);` |
| 124 | getsid | get session ID | `pid_t getsid(pid_t pid);` |
| 125 | capget | set/get capabilities of thread(s) | `int capget(cap_user_header_t hdrp, cap_user_data_t datap);` |
| 126 | capset | set/get capabilities of thread(s) | `int capget(cap_user_header_t hdrp, cap_user_data_t datap);` |
| 127 | rt_sigpending | examine pending signals | `int sigpending(sigset_t *set);` |
| 128 | rt_sigtimedwait | synchronously wait for queued signals | `int sigwaitinfo(const sigset_t *set, siginfo_t *info);` |
| 129 | rt_sigqueueinfo | queue a signal and data | `int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info);` |
| 130 | rt_sigsuspend | wait for a signal | `int sigsuspend(const sigset_t *mask);` |
| 131 | sigaltstack | set and/or get signal stack context | `int sigaltstack(const stack_t *ss, stack_t *old_ss);` |
| 132 | utime | change file last access and modification times | `int utime(const char *filename, const struct utimbuf *times);` |
| 133 | mknod | create a special or ordinary file | `int mknod(const char *pathname, mode_t mode, dev_t dev);` |
| 134 | uselib | load shared library | `int uselib(const char *library);` |
| 135 | personality | set the process execution domain | `int personality(unsigned long persona);` |
| 136 | ustat | get filesystem statistics | `int ustat(dev_t dev, struct ustat *ubuf);` |
| 137 | statfs | get filesystem statistics | `int statfs(const char *path, struct statfs *buf);` |
| 138 | fstatfs | get filesystem statistics | `int statfs(const char *path, struct statfs *buf);` |
| 139 | sysfs | get filesystem type information | `int sysfs(int option, const char *fsname);` |
| 140 | getpriority | get/set program scheduling priority | `int getpriority(int which, id_t who);` |
| 141 | setpriority | get/set program scheduling priority | `int getpriority(int which, id_t who);` |
| 142 | sched_setparam | set and get scheduling parameters | `int sched_setparam(pid_t pid, const struct sched_param *param);` |
| 143 | sched_getparam | set and get scheduling parameters | `int sched_setparam(pid_t pid, const struct sched_param *param);` |
| 144 | sched_setscheduler | set and get scheduling policy/parameters | `int sched_setscheduler(pid_t pid, int policy,` |
| 145 | sched_getscheduler | set and get scheduling policy/parameters | `int sched_setscheduler(pid_t pid, int policy,` |
| 146 | sched_get_priority_max | get static priority range | `int sched_get_priority_max(int policy);` |
| 147 | sched_get_priority_min | get static priority range | `int sched_get_priority_max(int policy);` |
| 148 | sched_rr_get_interval | get the SCHED_RR interval for the named process | `int sched_rr_get_interval(pid_t pid, struct timespec *tp);` |
| 149 | mlock | lock and unlock memory | `int mlock(const void *addr, size_t len);` |
| 150 | munlock | lock and unlock memory | `int mlock(const void *addr, size_t len);` |
| 151 | mlockall | lock and unlock memory | `int mlock(const void *addr, size_t len);` |
| 152 | munlockall | lock and unlock memory | `int mlock(const void *addr, size_t len);` |
| 153 | vhangup | virtually hangup the current terminal | `int vhangup(void);` |
| 154 | modify_ldt | get or set a per-process LDT entry | `int modify_ldt(int func, void *ptr, unsigned long bytecount);` |
| 155 | pivot_root | change the root mount | `int pivot_root(const char *new_root, const char *put_old);` |
| 156 | _sysctl | read/write system parameters | `int _sysctl(struct __sysctl_args *args);` |
| 157 | prctl | operations on a process | `int prctl(int option, unsigned long arg2, unsigned long arg3,` |
| 158 | arch_prctl | set architecture-specific thread state | `int arch_prctl(int code, unsigned long addr);` |
| 159 | adjtimex | tune kernel clock | `int adjtimex(struct timex *buf);` |
| 160 | setrlimit | get/set resource limits | `int getrlimit(int resource, struct rlimit *rlim);` |
| 161 | chroot | change root directory | `int chroot(const char *path);` |
| 162 | sync | commit filesystem caches to disk | `void sync(void);` |
| 163 | acct | switch process accounting on or off | `int acct(const char *filename);` |
| 164 | settimeofday | get / set time | `int gettimeofday(struct timeval *tv, struct timezone *tz);` |
| 165 | mount | mount filesystem | `int mount(const char *source, const char *target,` |
| 166 | umount2 | unmount filesystem | `int umount(const char *target);` |
| 167 | swapon | start/stop swapping to file/device | `int swapon(const char *path, int swapflags);` |
| 168 | swapoff | start/stop swapping to file/device | `int swapon(const char *path, int swapflags);` |
| 169 | reboot | reboot or enable/disable Ctrl-Alt-Del | `/* Since kernel version 2.1.30 there are symbolic names LINUX_REBOOT_*` |
| 170 | sethostname | get/set hostname | `int gethostname(char *name, size_t len);` |
| 171 | setdomainname | get/set NIS domain name | `int getdomainname(char *name, size_t len);` |
| 172 | iopl | change I/O privilege level | `int iopl(int level);` |
| 173 | ioperm | set port input/output permissions | `int ioperm(unsigned long from, unsigned long num, int turn_on);` |
| 174 | create_module | create a loadable module entry | `caddr_t create_module(const char *name, size_t size);` |
| 175 | init_module | load a kernel module | `int init_module(void *module_image, unsigned long len,` |
| 176 | delete_module | unload a kernel module | `int delete_module(const char *name, int flags);` |
| 177 | get_kernel_syms | retrieve exported kernel and module symbols | `int get_kernel_syms(struct kernel_sym *table);` |
| 178 | query_module | query the kernel for various bits pertaining to modules | `int query_module(const char *name, int which, void *buf,` |
| 179 | quotactl | manipulate disk quotas | `int quotactl(int cmd, const char *special, int id, caddr_t addr);` |
| 180 | nfsservctl | syscall interface to kernel nfs daemon | `long nfsservctl(int cmd, struct nfsctl_arg *argp,` |
| 181 | getpmsg | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 182 | putpmsg | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 183 | afs_syscall | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 184 | tuxcall | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 185 | security | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 186 | gettid | get thread identification | `pid_t gettid(void);` |
| 187 | readahead | initiate file readahead into page cache | `ssize_t readahead(int fd, off64_t offset, size_t count);` |
| 188 | setxattr | set an extended attribute value | `int setxattr(const char *path, const char *name,` |
| 189 | lsetxattr | set an extended attribute value | `int setxattr(const char *path, const char *name,` |
| 190 | fsetxattr | set an extended attribute value | `int setxattr(const char *path, const char *name,` |
| 191 | getxattr | retrieve an extended attribute value | `ssize_t getxattr(const char *path, const char *name,` |
| 192 | lgetxattr | retrieve an extended attribute value | `ssize_t getxattr(const char *path, const char *name,` |
| 193 | fgetxattr | retrieve an extended attribute value | `ssize_t getxattr(const char *path, const char *name,` |
| 194 | listxattr | list extended attribute names | `ssize_t listxattr(const char *path, char *list, size_t size);` |
| 195 | llistxattr | list extended attribute names | `ssize_t listxattr(const char *path, char *list, size_t size);` |
| 196 | flistxattr | list extended attribute names | `ssize_t listxattr(const char *path, char *list, size_t size);` |
| 197 | removexattr | remove an extended attribute | `int removexattr(const char *path, const char *name);` |
| 198 | lremovexattr | remove an extended attribute | `int removexattr(const char *path, const char *name);` |
| 199 | fremovexattr | remove an extended attribute | `int removexattr(const char *path, const char *name);` |
| 200 | tkill | send a signal to a thread | `int tkill(int tid, int sig);` |
| 201 | time | get time in seconds | `time_t time(time_t *tloc);` |
| 202 | futex | fast user-space locking | `int futex(int *uaddr, int futex_op, int val,` |
| 203 | sched_setaffinity | set and get a thread's CPU affinity mask | `int sched_setaffinity(pid_t pid, size_t cpusetsize,` |
| 204 | sched_getaffinity | set and get a thread's CPU affinity mask | `int sched_setaffinity(pid_t pid, size_t cpusetsize,` |
| 205 | set_thread_area | manipulate thread-local storage information | `int get_thread_area(struct user_desc *u_info);` |
| 206 | io_setup | create an asynchronous I/O context | `int io_setup(unsigned nr_events, aio_context_t *ctx_idp);` |
| 207 | io_destroy | destroy an asynchronous I/O context | `int io_destroy(aio_context_t ctx_id);` |
| 208 | io_getevents | read asynchronous I/O events from the completion queue | `int io_getevents(aio_context_t ctx_id, long min_nr, long nr,` |
| 209 | io_submit | submit asynchronous I/O blocks for processing | `int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);` |
| 210 | io_cancel | cancel an outstanding asynchronous I/O operation | `int io_cancel(aio_context_t ctx_id, struct iocb *iocb,` |
| 211 | get_thread_area | manipulate thread-local storage information | `int get_thread_area(struct user_desc *u_info);` |
| 212 | lookup_dcookie | return a directory entry's path | `int lookup_dcookie(u64 cookie, char *buffer, size_t len);` |
| 213 | epoll_create | open an epoll file descriptor | `int epoll_create(int size);` |
| 214 | epoll_ctl_old | Description not found | `Signature not found` |
| 215 | epoll_wait_old | Description not found | `Signature not found` |
| 216 | remap_file_pages | create a nonlinear file mapping | `int remap_file_pages(void *addr, size_t size, int prot,` |
| 217 | getdents64 | get directory entries | `int getdents(unsigned int fd, struct linux_dirent *dirp,` |
| 218 | set_tid_address | set pointer to thread ID | `long set_tid_address(int *tidptr);` |
| 219 | restart_syscall | restart a system call after interruption by a stop signal | `int restart_syscall(void);` |
| 220 | semtimedop | System V semaphore operations | `int semop(int semid, struct sembuf *sops, size_t nsops);` |
| 221 | fadvise64 | predeclare an access pattern for file data | `int posix_fadvise(int fd, off_t offset, off_t len, int advice);` |
| 222 | timer_create | create a POSIX per-process timer | `int timer_create(clockid_t clockid, struct sigevent *sevp,` |
| 223 | timer_settime | arm/disarm and fetch state of POSIX per-process timer | `int timer_settime(timer_t timerid, int flags,` |
| 224 | timer_gettime | arm/disarm and fetch state of POSIX per-process timer | `int timer_settime(timer_t timerid, int flags,` |
| 225 | timer_getoverrun | get overrun count for a POSIX per-process timer | `int timer_getoverrun(timer_t timerid);` |
| 226 | timer_delete | delete a POSIX per-process timer | `int timer_delete(timer_t timerid);` |
| 227 | clock_settime | clock and time functions | `int clock_getres(clockid_t clk_id, struct timespec *res);` |
| 228 | clock_gettime | clock and time functions | `int clock_getres(clockid_t clk_id, struct timespec *res);` |
| 229 | clock_getres | clock and time functions | `int clock_getres(clockid_t clk_id, struct timespec *res);` |
| 230 | clock_nanosleep | high-resolution sleep with specifiable clock | `int clock_nanosleep(clockid_t clock_id, int flags,` |
| 231 | exit_group | exit all threads in a process | `void exit_group(int status);` |
| 232 | epoll_wait | wait for an I/O event on an epoll file descriptor | `int epoll_wait(int epfd, struct epoll_event *events,` |
| 233 | epoll_ctl | control interface for an epoll file descriptor | `int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);` |
| 234 | tgkill | send a signal to a thread | `int tkill(int tid, int sig);` |
| 235 | utimes | change file last access and modification times | `int utime(const char *filename, const struct utimbuf *times);` |
| 236 | vserver | afs_syscall,  break,  fattach,  fdetach,  ftime,  getmsg, getpmsg, gtty, isastream, lock, madvise1, mpx, prof, profil, putmsg, putpmsg, security, | `Unimplemented system calls.` |
| 237 | mbind | set memory policy for a memory range | `long mbind(void *addr, unsigned long len, int mode,` |
| 238 | set_mempolicy | set default NUMA memory policy for a thread and its children | `long set_mempolicy(int mode, const unsigned long *nodemask,` |
| 239 | get_mempolicy | retrieve NUMA memory policy for a thread | `long get_mempolicy(int *mode, unsigned long *nodemask,` |
| 240 | mq_open | open a message queue | `mqd_t mq_open(const char *name, int oflag);` |
| 241 | mq_unlink | remove a message queue | `int mq_unlink(const char *name);` |
| 242 | mq_timedsend | send a message to a message queue | `int mq_send(mqd_t mqdes, const char *msg_ptr,` |
| 243 | mq_timedreceive | receive a message from a message queue | `ssize_t mq_receive(mqd_t mqdes, char *msg_ptr,` |
| 244 | mq_notify | register for notification when a message is available | `int mq_notify(mqd_t mqdes, const struct sigevent *sevp);` |
| 245 | mq_getsetattr | get/set message queue attributes | `int mq_getsetattr(mqd_t mqdes, struct mq_attr *newattr,` |
| 246 | kexec_load | load a new kernel for later execution | `long kexec_load(unsigned long entry, unsigned long nr_segments,` |
| 247 | waitid | wait for process to change state | `pid_t wait(int *wstatus);` |
| 248 | add_key | add a key to the kernel's key management facility | `key_serial_t add_key(const char *type, const char *description,` |
| 249 | request_key | request a key from the kernel's key management facility | `key_serial_t request_key(const char *type, const char *description,` |
| 250 | keyctl | manipulate the kernel's key management facility | `long keyctl(int operation, ...)` |
| 251 | ioprio_set | get/set I/O scheduling class and priority | `int ioprio_get(int which, int who);` |
| 252 | ioprio_get | get/set I/O scheduling class and priority | `int ioprio_get(int which, int who);` |
| 253 | inotify_init | initialize an inotify instance | `int inotify_init(void);` |
| 254 | inotify_add_watch | add a watch to an initialized inotify instance | `int inotify_add_watch(int fd, const char *pathname, uint32_t mask);` |
| 255 | inotify_rm_watch | remove an existing watch from an inotify instance | `int inotify_rm_watch(int fd, int wd);` |
| 256 | migrate_pages | move all pages in a process to another set of nodes | `long migrate_pages(int pid, unsigned long maxnode,` |
| 257 | openat | open and possibly create a file | `int open(const char *pathname, int flags);` |
| 258 | mkdirat | create a directory | `int mkdir(const char *pathname, mode_t mode);` |
| 259 | mknodat | create a special or ordinary file | `int mknod(const char *pathname, mode_t mode, dev_t dev);` |
| 260 | fchownat | change ownership of a file | `int chown(const char *pathname, uid_t owner, gid_t group);` |
| 261 | futimesat | change timestamps of a file relative to a directory file descriptor | `int futimesat(int dirfd, const char *pathname,` |
| 262 | newfstatat | get file status | `int stat(const char *pathname, struct stat *statbuf);` |
| 263 | unlinkat | delete a name and possibly the file it refers to | `int unlink(const char *pathname);` |
| 264 | renameat | change the name or location of a file | `int rename(const char *oldpath, const char *newpath);` |
| 265 | linkat | make a new name for a file | `int link(const char *oldpath, const char *newpath);` |
| 266 | symlinkat | make a new name for a file | `int symlink(const char *target, const char *linkpath);` |
| 267 | readlinkat | read value of a symbolic link | `ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);` |
| 268 | fchmodat | change permissions of a file | `int chmod(const char *pathname, mode_t mode);` |
| 269 | faccessat | check user's permissions for a file | `int access(const char *pathname, int mode);` |
| 270 | pselect6 | synchronous I/O multiplexing | `/* According to POSIX.1-2001, POSIX.1-2008 */` |
| 271 | ppoll | wait for some event on a file descriptor | `int poll(struct pollfd *fds, nfds_t nfds, int timeout);` |
| 272 | unshare | disassociate parts of the process execution context | `int unshare(int flags);` |
| 273 | set_robust_list | get/set list of robust futexes | `long get_robust_list(int pid, struct robust_list_head **head_ptr,` |
| 274 | get_robust_list | get/set list of robust futexes | `long get_robust_list(int pid, struct robust_list_head **head_ptr,` |
| 275 | splice | splice data to/from a pipe | `ssize_t splice(int fd_in, loff_t *off_in, int fd_out,` |
| 276 | tee | duplicating pipe content | `ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);` |
| 277 | sync_file_range | sync a file segment with disk | `int sync_file_range(int fd, off64_t offset, off64_t nbytes,` |
| 278 | vmsplice | splice user pages to/from a pipe | `ssize_t vmsplice(int fd, const struct iovec *iov,` |
| 279 | move_pages | move individual pages of a process to another node | `long move_pages(int pid, unsigned long count, void **pages,` |
| 280 | utimensat | change file timestamps with nanosecond precision | `int utimensat(int dirfd, const char *pathname,` |
| 281 | epoll_pwait | wait for an I/O event on an epoll file descriptor | `int epoll_wait(int epfd, struct epoll_event *events,` |
| 282 | signalfd | create a file descriptor for accepting signals | `int signalfd(int fd, const sigset_t *mask, int flags);` |
| 283 | timerfd_create | timers that notify via file descriptors | `int timerfd_create(int clockid, int flags);` |
| 284 | eventfd | create a file descriptor for event notification | `int eventfd(unsigned int initval, int flags);` |
| 285 | fallocate | manipulate file space | `int fallocate(int fd, int mode, off_t offset, off_t len);` |
| 286 | timerfd_settime | timers that notify via file descriptors | `int timerfd_create(int clockid, int flags);` |
| 287 | timerfd_gettime | timers that notify via file descriptors | `int timerfd_create(int clockid, int flags);` |
| 288 | accept4 | accept a connection on a socket | `int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);` |
| 289 | signalfd4 | create a file descriptor for accepting signals | `int signalfd(int fd, const sigset_t *mask, int flags);` |
| 290 | eventfd2 | create a file descriptor for event notification | `int eventfd(unsigned int initval, int flags);` |
| 291 | epoll_create1 | open an epoll file descriptor | `int epoll_create(int size);` |
| 292 | dup3 | duplicate a file descriptor | `int dup(int oldfd);` |
| 293 | pipe2 | create pipe | `/* On Alpha, IA-64, MIPS, SuperH, and SPARC/SPARC64; see NOTES */` |
| 294 | inotify_init1 | initialize an inotify instance | `int inotify_init(void);` |
| 295 | preadv | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 296 | pwritev | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 297 | rt_tgsigqueueinfo | queue a signal and data | `int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info);` |
| 298 | perf_event_open | set up performance monitoring | `int perf_event_open(struct perf_event_attr *attr,` |
| 299 | recvmmsg | receive multiple messages on a socket | `int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,` |
| 300 | fanotify_init | create and initialize fanotify group | `int fanotify_init(unsigned int flags, unsigned int event_f_flags);` |
| 301 | fanotify_mark | add, remove, or modify an fanotify mark on a filesystem object | `int fanotify_mark(int fanotify_fd, unsigned int flags,` |
| 302 | prlimit64 | get/set resource limits | `int getrlimit(int resource, struct rlimit *rlim);` |
| 303 | name_to_handle_at | obtain handle for a pathname and open file via a handle | `int name_to_handle_at(int dirfd, const char *pathname,` |
| 304 | open_by_handle_at | obtain handle for a pathname and open file via a handle | `int name_to_handle_at(int dirfd, const char *pathname,` |
| 305 | clock_adjtime | Description not found | `Signature not found` |
| 306 | syncfs | commit filesystem caches to disk | `void sync(void);` |
| 307 | sendmmsg | send multiple messages on a socket | `int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,` |
| 308 | setns | reassociate thread with a namespace | `int setns(int fd, int nstype);` |
| 309 | getcpu | determine CPU and NUMA node on which the calling thread is running | `int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);` |
| 310 | process_vm_readv | transfer data between process address spaces | `ssize_t process_vm_readv(pid_t pid,` |
| 311 | process_vm_writev | transfer data between process address spaces | `ssize_t process_vm_readv(pid_t pid,` |
| 312 | kcmp | compare two processes to determine if they share a kernel resource | `int kcmp(pid_t pid1, pid_t pid2, int type,` |
| 313 | finit_module | load a kernel module | `int init_module(void *module_image, unsigned long len,` |
| 314 | sched_setattr | set and get scheduling policy and attributes | `int sched_setattr(pid_t pid, struct sched_attr *attr,` |
| 315 | sched_getattr | set and get scheduling policy and attributes | `int sched_setattr(pid_t pid, struct sched_attr *attr,` |
| 316 | renameat2 | change the name or location of a file | `int rename(const char *oldpath, const char *newpath);` |
| 317 | seccomp | operate on Secure Computing state of the process | `int seccomp(unsigned int operation, unsigned int flags, void *args);` |
| 318 | getrandom | obtain a series of random bytes | `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);` |
| 319 | memfd_create | create an anonymous file | `int memfd_create(const char *name, unsigned int flags);` |
| 320 | kexec_file_load | load a new kernel for later execution | `long kexec_load(unsigned long entry, unsigned long nr_segments,` |
| 321 | bpf | perform a command on an extended BPF map or program | `int bpf(int cmd, union bpf_attr *attr, unsigned int size);` |
| 322 | execveat | execute program relative to a directory file descriptor | `int execveat(int dirfd, const char *pathname,` |
| 323 | userfaultfd | create a file descriptor for handling page faults in user space | `int userfaultfd(int flags);` |
| 324 | membarrier | issue memory barriers on a set of threads | `int membarrier(int cmd, int flags);` |
| 325 | mlock2 | lock and unlock memory | `int mlock(const void *addr, size_t len);` |
| 326 | copy_file_range | Copy a range of data from one file to another | `ssize_t copy_file_range(int fd_in, loff_t *off_in,` |
| 327 | preadv2 | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 328 | pwritev2 | read or write data into multiple buffers | `ssize_t readv(int fd, const struct iovec *iov, int iovcnt);` |
| 329 | pkey_mprotect | set protection on a region of memory | `int mprotect(void *addr, size_t len, int prot);` |
| 330 | pkey_alloc | allocate or free a protection key | `int pkey_alloc(unsigned int flags, unsigned int access_rights);` |
| 331 | pkey_free | allocate or free a protection key | `int pkey_alloc(unsigned int flags, unsigned int access_rights);` |
| 332 | statx | get file status (extended) | `int statx(int dirfd, const char *pathname, int flags,` |
| 333 | io_pgetevents | Description not found | `Signature not found` |
| 334 | rseq | Description not found | `Signature not found` |
| 424 | pidfd_send_signal | send a signal to a process specified by a file descriptor | `int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,` |
| 425 | io_uring_setup | Description not found | `Signature not found` |
| 426 | io_uring_enter | Description not found | `Signature not found` |
| 427 | io_uring_register | Description not found | `Signature not found` |
| 428 | open_tree | Description not found | `Signature not found` |
| 429 | move_mount | Description not found | `Signature not found` |
| 430 | fsopen | Description not found | `Signature not found` |
| 431 | fsconfig | Description not found | `Signature not found` |
| 432 | fsmount | Description not found | `Signature not found` |
| 433 | fspick | Description not found | `Signature not found` |
| 434 | pidfd_open | obtain a file descriptor that refers to a process | `int pidfd_open(pid_t pid, unsigned int flags);` |
| 435 | clone3 | create a child process | `/* Prototype for the glibc wrapper function */` |
