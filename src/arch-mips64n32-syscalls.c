/**
 * Enhanced Seccomp MIPS Specific Code
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 *
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <string.h>

#include <seccomp.h>

#include "arch.h"
#include "arch-mips64n32.h"

/* N32 ABI */
#define __NR_SYSCALL_BASE	6000

/* NOTE: based on Linux 3.19 */
const struct arch_syscall_def mips64n32_syscall_table[] = { \
	{ "_llseek", __PNR__llseek },
	{ "_newselect", (__NR_SYSCALL_BASE + 22) },
	{ "_sysctl", (__NR_SYSCALL_BASE + 152) },
	{ "accept", (__NR_SYSCALL_BASE + 42) },
	{ "accept4", (__NR_SYSCALL_BASE + 297) },
	{ "access", (__NR_SYSCALL_BASE + 20) },
	{ "acct", (__NR_SYSCALL_BASE + 158) },
	{ "add_key", (__NR_SYSCALL_BASE + 243) },
	{ "adjtimex", (__NR_SYSCALL_BASE + 154) },
	{ "afs_syscall", (__NR_SYSCALL_BASE + 176) },
	{ "alarm", (__NR_SYSCALL_BASE + 37) },
	{ "arm_fadvise64_64", __PNR_arm_fadvise64_64 },
	{ "arm_sync_file_range", __PNR_arm_sync_file_range },
	{ "arch_prctl", __PNR_arch_prctl },
	{ "bdflush", __PNR_bdflush },
	{ "bind", (__NR_SYSCALL_BASE + 48) },
	{ "bpf", (__NR_SYSCALL_BASE + 319) },
	{ "break", __PNR_break },
	{ "breakpoint", __PNR_breakpoint },
	{ "brk", (__NR_SYSCALL_BASE + 12) },
	{ "cachectl", (__NR_SYSCALL_BASE + 198) },
	{ "cacheflush", (__NR_SYSCALL_BASE + 197) },
	{ "capget", (__NR_SYSCALL_BASE + 123) },
	{ "capset", (__NR_SYSCALL_BASE + 124) },
	{ "chdir", (__NR_SYSCALL_BASE + 78) },
	{ "chmod", (__NR_SYSCALL_BASE + 88) },
	{ "chown", (__NR_SYSCALL_BASE + 90) },
	{ "chown32", __PNR_chown32 },
	{ "chroot", (__NR_SYSCALL_BASE + 156) },
	{ "clock_adjtime", (__NR_SYSCALL_BASE + 305) },
	{ "clock_getres", (__NR_SYSCALL_BASE + 227) },
	{ "clock_gettime", (__NR_SYSCALL_BASE + 226) },
	{ "clock_nanosleep", (__NR_SYSCALL_BASE + 228) },
	{ "clock_settime", (__NR_SYSCALL_BASE + 225) },
	{ "clone", (__NR_SYSCALL_BASE + 55) },
	{ "close", (__NR_SYSCALL_BASE + 3) },
	{ "connect", (__NR_SYSCALL_BASE + 41) },
	{ "creat", (__NR_SYSCALL_BASE + 83) },
	{ "create_module", (__NR_SYSCALL_BASE + 167) },
	{ "delete_module", (__NR_SYSCALL_BASE + 169) },
	{ "dup", (__NR_SYSCALL_BASE + 31) },
	{ "dup2", (__NR_SYSCALL_BASE + 32) },
	{ "dup3", (__NR_SYSCALL_BASE + 290) },
	{ "epoll_create", (__NR_SYSCALL_BASE + 207) },
	{ "epoll_create1", (__NR_SYSCALL_BASE + 289) },
	{ "epoll_ctl", (__NR_SYSCALL_BASE + 208) },
	{ "epoll_ctl_old", __PNR_epoll_ctl_old },
	{ "epoll_pwait", (__NR_SYSCALL_BASE + 276) },
	{ "epoll_wait", (__NR_SYSCALL_BASE + 209) },
	{ "epoll_wait_old", __PNR_epoll_wait_old },
	{ "eventfd", (__NR_SYSCALL_BASE + 282) },
	{ "eventfd2", (__NR_SYSCALL_BASE + 288) },
	{ "execve", (__NR_SYSCALL_BASE + 57) },
	{ "execveat", (__NR_SYSCALL_BASE + 320) },
	{ "exit", (__NR_SYSCALL_BASE + 58) },
	{ "exit_group", (__NR_SYSCALL_BASE + 205) },
	{ "faccessat", (__NR_SYSCALL_BASE + 263) },
	{ "fadvise64", (__NR_SYSCALL_BASE + 216) },
	{ "fadvise64_64", __PNR_fadvise64_64 },
	{ "fallocate", (__NR_SYSCALL_BASE + 283) },
	{ "fanotify_init", (__NR_SYSCALL_BASE + 300) },
	{ "fanotify_mark", (__NR_SYSCALL_BASE + 301) },
	{ "fchdir", (__NR_SYSCALL_BASE + 79) },
	{ "fchmod", (__NR_SYSCALL_BASE + 89) },
	{ "fchmodat", (__NR_SYSCALL_BASE + 262) },
	{ "fchown", (__NR_SYSCALL_BASE + 91) },
	{ "fchown32", __PNR_fchown32 },
	{ "fchownat", (__NR_SYSCALL_BASE + 254) },
	{ "fcntl", (__NR_SYSCALL_BASE + 70) },
	{ "fcntl64", (__NR_SYSCALL_BASE + 212) },
	{ "fdatasync", (__NR_SYSCALL_BASE + 73) },
	{ "fgetxattr", (__NR_SYSCALL_BASE + 185) },
	{ "finit_module", (__NR_SYSCALL_BASE + 312) },
	{ "flistxattr", (__NR_SYSCALL_BASE + 188) },
	{ "flock", (__NR_SYSCALL_BASE + 71) },
	{ "fork", (__NR_SYSCALL_BASE + 56) },
	{ "fremovexattr", (__NR_SYSCALL_BASE + 191) },
	{ "fsetxattr", (__NR_SYSCALL_BASE + 182) },
	{ "fstat", (__NR_SYSCALL_BASE + 5) },
	{ "fstat64", __PNR_fstat64 },
	{ "fstatat64", __PNR_fstat64 },
	{ "fstatfs", (__NR_SYSCALL_BASE + 135) },
	{ "fstatfs64", (__NR_SYSCALL_BASE + 218) },
	{ "fsync", (__NR_SYSCALL_BASE + 72) },
	{ "ftime", __PNR_ftime },
	{ "ftruncate", (__NR_SYSCALL_BASE + 75) },
	{ "ftruncate64", __PNR_ftruncate64 },
	{ "futex", (__NR_SYSCALL_BASE + 194) },
	{ "futimesat", (__NR_SYSCALL_BASE + 255) },
	{ "get_kernel_syms", (__NR_SYSCALL_BASE + 170) },
	{ "get_mempolicy", (__NR_SYSCALL_BASE + 232) },
	{ "get_robust_list", (__NR_SYSCALL_BASE + 273) },
	{ "get_thread_area", __PNR_get_thread_area },
	{ "getcpu", (__NR_SYSCALL_BASE + 275) },
	{ "getcwd", (__NR_SYSCALL_BASE + 77) },
	{ "getdents", (__NR_SYSCALL_BASE + 76) },
	{ "getdents64", (__NR_SYSCALL_BASE + 299) },
	{ "getegid", (__NR_SYSCALL_BASE + 106) },
	{ "getegid32", __PNR_getegid32 },
	{ "geteuid", (__NR_SYSCALL_BASE + 105) },
	{ "geteuid32", __PNR_geteuid32 },
	{ "getgid", (__NR_SYSCALL_BASE + 102) },
	{ "getgid32", __PNR_getgid32 },
	{ "getgroups", (__NR_SYSCALL_BASE + 113) },
	{ "getgroups32", __PNR_getgroups32 },
	{ "getitimer", (__NR_SYSCALL_BASE + 35) },
	{ "getpeername", (__NR_SYSCALL_BASE + 51) },
	{ "getpgid", (__NR_SYSCALL_BASE + 119) },
	{ "getpgrp", (__NR_SYSCALL_BASE + 109) },
	{ "getpid", (__NR_SYSCALL_BASE + 38) },
	{ "getpmsg", (__NR_SYSCALL_BASE + 174) },
	{ "getppid", (__NR_SYSCALL_BASE + 108) },
	{ "getpriority", (__NR_SYSCALL_BASE + 137) },
	{ "getrandom", (__NR_SYSCALL_BASE + 317) },
	{ "getresgid", (__NR_SYSCALL_BASE + 118) },
	{ "getresgid32", __PNR_getresgid32 },
	{ "getresuid", (__NR_SYSCALL_BASE + 116) },
	{ "getresuid32", __PNR_getresuid32 },
	{ "getrlimit", (__NR_SYSCALL_BASE + 95) },
	{ "getrusage", (__NR_SYSCALL_BASE + 96) },
	{ "getsid", (__NR_SYSCALL_BASE + 122) },
	{ "getsockname", (__NR_SYSCALL_BASE + 50) },
	{ "getsockopt", (__NR_SYSCALL_BASE + 54) },
	{ "gettid", (__NR_SYSCALL_BASE + 178) },
	{ "gettimeofday", (__NR_SYSCALL_BASE + 94) },
	{ "getuid", (__NR_SYSCALL_BASE + 100) },
	{ "getuid32", __PNR_getuid32 },
	{ "getxattr", (__NR_SYSCALL_BASE + 183) },
	{ "gtty", __PNR_gtty },
	{ "idle", __PNR_idle },
	{ "init_module", (__NR_SYSCALL_BASE + 168) },
	{ "inotify_add_watch", (__NR_SYSCALL_BASE + 248) },
	{ "inotify_init", (__NR_SYSCALL_BASE + 247) },
	{ "inotify_init1", (__NR_SYSCALL_BASE + 292) },
	{ "inotify_rm_watch", (__NR_SYSCALL_BASE + 249) },
	{ "io_cancel", (__NR_SYSCALL_BASE + 204) },
	{ "io_destroy", (__NR_SYSCALL_BASE + 201) },
	{ "io_getevents", (__NR_SYSCALL_BASE + 202) },
	{ "io_setup", (__NR_SYSCALL_BASE + 200) },
	{ "io_submit", (__NR_SYSCALL_BASE + 203) },
	{ "ioctl", (__NR_SYSCALL_BASE + 15) },
	{ "ioperm", __PNR_ioperm },
	{ "iopl", __PNR_iopl },
	{ "ioprio_get", (__NR_SYSCALL_BASE + 278) },
	{ "ioprio_set", (__NR_SYSCALL_BASE + 277) },
	{ "ipc", __PNR_ipc },
	{ "kcmp", (__NR_SYSCALL_BASE + 311) },
	{ "kexec_file_load", __PNR_kexec_file_load },
	{ "kexec_load", (__NR_SYSCALL_BASE + 274) },
	{ "keyctl", (__NR_SYSCALL_BASE + 245) },
	{ "kill", (__NR_SYSCALL_BASE + 60) },
	{ "lchown", (__NR_SYSCALL_BASE + 92) },
	{ "lchown32", __PNR_lchown32 },
	{ "lgetxattr", (__NR_SYSCALL_BASE + 184) },
	{ "link", (__NR_SYSCALL_BASE + 84) },
	{ "linkat", (__NR_SYSCALL_BASE + 259) },
	{ "listen", (__NR_SYSCALL_BASE + 49) },
	{ "listxattr", (__NR_SYSCALL_BASE + 186) },
	{ "llistxattr", (__NR_SYSCALL_BASE + 187) },
	{ "lock", __PNR_lock },
	{ "lookup_dcookie", (__NR_SYSCALL_BASE + 206) },
	{ "lremovexattr", (__NR_SYSCALL_BASE + 190) },
	{ "lseek", (__NR_SYSCALL_BASE + 8) },
	{ "lsetxattr", (__NR_SYSCALL_BASE + 181) },
	{ "lstat", (__NR_SYSCALL_BASE + 6) },
	{ "lstat64", __PNR_lstat64 },
	{ "madvise", (__NR_SYSCALL_BASE + 27) },
	{ "mbind", (__NR_SYSCALL_BASE + 231) },
	{ "memfd_create", (__NR_SYSCALL_BASE + 318) },
	{ "migrate_pages", (__NR_SYSCALL_BASE + 250) },
	{ "mincore", (__NR_SYSCALL_BASE + 26) },
	{ "mkdir", (__NR_SYSCALL_BASE + 81) },
	{ "mkdirat", (__NR_SYSCALL_BASE + 252) },
	{ "mknod", (__NR_SYSCALL_BASE + 131) },
	{ "mknodat", (__NR_SYSCALL_BASE + 253) },
	{ "mlock", (__NR_SYSCALL_BASE + 146) },
	{ "mlockall", (__NR_SYSCALL_BASE + 148) },
	{ "mmap", (__NR_SYSCALL_BASE + 9) },
	{ "mmap2", __PNR_mmap2 },
	{ "modify_ldt", __PNR_modify_ldt },
	{ "mount", (__NR_SYSCALL_BASE + 160) },
	{ "move_pages", (__NR_SYSCALL_BASE + 271) },
	{ "mprotect", (__NR_SYSCALL_BASE + 10) },
	{ "mpx", __PNR_mpx },
	{ "mq_getsetattr", (__NR_SYSCALL_BASE + 239) },
	{ "mq_notify", (__NR_SYSCALL_BASE + 238) },
	{ "mq_open", (__NR_SYSCALL_BASE + 234) },
	{ "mq_timedreceive", (__NR_SYSCALL_BASE + 237) },
	{ "mq_timedsend", (__NR_SYSCALL_BASE + 236) },
	{ "mq_unlink", (__NR_SYSCALL_BASE + 235) },
	{ "mremap", (__NR_SYSCALL_BASE + 24) },
	{ "msgctl", (__NR_SYSCALL_BASE + 69) },
	{ "msgget", (__NR_SYSCALL_BASE + 66) },
	{ "msgrcv", (__NR_SYSCALL_BASE + 68) },
	{ "msgsnd", (__NR_SYSCALL_BASE + 67) },
	{ "msync", (__NR_SYSCALL_BASE + 25) },
	{ "munlock", (__NR_SYSCALL_BASE + 147) },
	{ "munlockall", (__NR_SYSCALL_BASE + 149) },
	{ "munmap", (__NR_SYSCALL_BASE + 11) },
	{ "name_to_handle_at", (__NR_SYSCALL_BASE + 303) },
	{ "nanosleep", (__NR_SYSCALL_BASE + 34) },
	{ "newfstatat", (__NR_SYSCALL_BASE + 256) },
	{ "nfsservctl", (__NR_SYSCALL_BASE + 173) },
	{ "nice", __PNR_nice },
	{ "oldfstat", __PNR_oldfstat },
	{ "oldlstat", __PNR_oldlstat },
	{ "oldolduname", __PNR_oldolduname },
	{ "oldstat", __PNR_oldstat },
	{ "olduname", __PNR_olduname },
	{ "oldwait4", __PNR_oldwait4 },
	{ "open", (__NR_SYSCALL_BASE + 2) },
	{ "open_by_handle_at", (__NR_SYSCALL_BASE + 304) },
	{ "openat", (__NR_SYSCALL_BASE + 251) },
	{ "pause", (__NR_SYSCALL_BASE + 33) },
	{ "pciconfig_iobase", __PNR_pciconfig_iobase },
	{ "pciconfig_read", __PNR_pciconfig_read },
	{ "pciconfig_write", __PNR_pciconfig_write },
	{ "perf_event_open", (__NR_SYSCALL_BASE + 296) },
	{ "personality", (__NR_SYSCALL_BASE + 132) },
	{ "pipe", (__NR_SYSCALL_BASE + 21) },
	{ "pipe2", (__NR_SYSCALL_BASE + 291) },
	{ "pivot_root", (__NR_SYSCALL_BASE + 151) },
	{ "poll", (__NR_SYSCALL_BASE + 7) },
	{ "ppoll", (__NR_SYSCALL_BASE + 265) },
	{ "prctl", (__NR_SYSCALL_BASE + 153) },
	{ "pread64", (__NR_SYSCALL_BASE + 16) },
	{ "preadv", (__NR_SYSCALL_BASE + 293) },
	{ "prlimit64", (__NR_SYSCALL_BASE + 302) },
	{ "process_vm_readv", (__NR_SYSCALL_BASE + 309) },
	{ "process_vm_writev", (__NR_SYSCALL_BASE + 310) },
	{ "prof", __PNR_prof },
	{ "profil", __PNR_profil },
	{ "pselect6", (__NR_SYSCALL_BASE + 264) },
	{ "ptrace", (__NR_SYSCALL_BASE + 99) },
	{ "putpmsg", (__NR_SYSCALL_BASE + 175) },
	{ "pwrite64", (__NR_SYSCALL_BASE + 17) },
	{ "pwritev", (__NR_SYSCALL_BASE + 294) },
	{ "query_module", (__NR_SYSCALL_BASE + 171) },
	{ "quotactl", (__NR_SYSCALL_BASE + 172) },
	{ "read", (__NR_SYSCALL_BASE + 0) },
	{ "readahead", (__NR_SYSCALL_BASE + 179) },
	{ "readdir", __PNR_readdir },
	{ "readlink", (__NR_SYSCALL_BASE + 87) },
	{ "readlinkat", (__NR_SYSCALL_BASE + 261) },
	{ "readv", (__NR_SYSCALL_BASE + 18) },
	{ "reboot", (__NR_SYSCALL_BASE + 164) },
	{ "recv", __PNR_recv },
	{ "recvfrom", (__NR_SYSCALL_BASE + 44) },
	{ "recvmmsg", (__NR_SYSCALL_BASE + 298) },
	{ "recvmsg", (__NR_SYSCALL_BASE + 46) },
	{ "remap_file_pages", (__NR_SYSCALL_BASE + 210) },
	{ "removexattr", (__NR_SYSCALL_BASE + 189) },
	{ "rename", (__NR_SYSCALL_BASE + 80) },
	{ "renameat", (__NR_SYSCALL_BASE + 258) },
	{ "renameat2", (__NR_SYSCALL_BASE + 315) },
	{ "request_key", (__NR_SYSCALL_BASE + 244) },
	{ "restart_syscall", (__NR_SYSCALL_BASE + 214) },
	{ "rmdir", (__NR_SYSCALL_BASE + 82) },
	{ "rt_sigaction", (__NR_SYSCALL_BASE + 13) },
	{ "rt_sigpending", (__NR_SYSCALL_BASE + 125) },
	{ "rt_sigprocmask", (__NR_SYSCALL_BASE + 14) },
	{ "rt_sigqueueinfo", (__NR_SYSCALL_BASE + 127) },
	{ "rt_sigreturn", (__NR_SYSCALL_BASE + 211) },
	{ "rt_sigsuspend", (__NR_SYSCALL_BASE + 128) },
	{ "rt_sigtimedwait", (__NR_SYSCALL_BASE + 126) },
	{ "rt_tgsigqueueinfo", (__NR_SYSCALL_BASE + 295) },
	{ "sched_get_priority_max", (__NR_SYSCALL_BASE + 143) },
	{ "sched_get_priority_min", (__NR_SYSCALL_BASE + 144) },
	{ "sched_getaffinity", (__NR_SYSCALL_BASE + 196) },
	{ "sched_getattr", (__NR_SYSCALL_BASE + 314) },
	{ "sched_getparam", (__NR_SYSCALL_BASE + 140) },
	{ "sched_getscheduler", (__NR_SYSCALL_BASE + 142) },
	{ "sched_rr_get_interval", (__NR_SYSCALL_BASE + 145) },
	{ "sched_setaffinity", (__NR_SYSCALL_BASE + 195) },
	{ "sched_setattr", (__NR_SYSCALL_BASE + 313) },
	{ "sched_setparam", (__NR_SYSCALL_BASE + 139) },
	{ "sched_setscheduler", (__NR_SYSCALL_BASE + 141) },
	{ "sched_yield", (__NR_SYSCALL_BASE + 23) },
	{ "seccomp", (__NR_SYSCALL_BASE + 316) },
	{ "security", __PNR_security },
	{ "select", __PNR_select },
	{ "semctl", (__NR_SYSCALL_BASE + 64) },
	{ "semget", (__NR_SYSCALL_BASE + 62) },
	{ "semop", (__NR_SYSCALL_BASE + 63) },
	{ "semtimedop", (__NR_SYSCALL_BASE + 215) },
	{ "send", __PNR_send },
	{ "sendfile", (__NR_SYSCALL_BASE + 39) },
	{ "sendfile64", (__NR_SYSCALL_BASE + 219) },
	{ "sendmmsg", (__NR_SYSCALL_BASE + 307) },
	{ "sendmsg", (__NR_SYSCALL_BASE + 45) },
	{ "sendto", (__NR_SYSCALL_BASE + 43) },
	{ "set_mempolicy", (__NR_SYSCALL_BASE + 233) },
	{ "set_robust_list", (__NR_SYSCALL_BASE + 272) },
	{ "set_thread_area", (__NR_SYSCALL_BASE + 246) },
	{ "set_tid_address", (__NR_SYSCALL_BASE + 213) },
	{ "set_tls", __PNR_set_tls },
	{ "setdomainname", (__NR_SYSCALL_BASE + 166) },
	{ "setfsgid", (__NR_SYSCALL_BASE + 121) },
	{ "setfsgid32", __PNR_setfsgid32 },
	{ "setfsuid", (__NR_SYSCALL_BASE + 120) },
	{ "setfsuid32", __PNR_setfsuid32 },
	{ "setgid", (__NR_SYSCALL_BASE + 104) },
	{ "setgid32", __PNR_setgid32 },
	{ "setgroups", (__NR_SYSCALL_BASE + 114) },
	{ "setgroups32", __PNR_setgroups32 },
	{ "sethostname", (__NR_SYSCALL_BASE + 165) },
	{ "setitimer", (__NR_SYSCALL_BASE + 36) },
	{ "setns", (__NR_SYSCALL_BASE + 308) },
	{ "setpgid", (__NR_SYSCALL_BASE + 107) },
	{ "setpriority", (__NR_SYSCALL_BASE + 138) },
	{ "setregid", (__NR_SYSCALL_BASE + 112) },
	{ "setregid32", __PNR_setregid32 },
	{ "setresgid", (__NR_SYSCALL_BASE + 117) },
	{ "setresgid32", __PNR_setresgid32 },
	{ "setresuid", (__NR_SYSCALL_BASE + 115) },
	{ "setresuid32", __PNR_setresuid32 },
	{ "setreuid", (__NR_SYSCALL_BASE + 111) },
	{ "setreuid32", __PNR_setreuid32 },
	{ "setrlimit", (__NR_SYSCALL_BASE + 155) },
	{ "setsid", (__NR_SYSCALL_BASE + 110) },
	{ "setsockopt", (__NR_SYSCALL_BASE + 53) },
	{ "settimeofday", (__NR_SYSCALL_BASE + 159) },
	{ "setuid", (__NR_SYSCALL_BASE + 103) },
	{ "setuid32", __PNR_setuid32 },
	{ "setxattr", (__NR_SYSCALL_BASE + 180) },
	{ "sgetmask", __PNR_sgetmask },
	{ "shmat", (__NR_SYSCALL_BASE + 29) },
	{ "shmctl", (__NR_SYSCALL_BASE + 30) },
	{ "shmdt", (__NR_SYSCALL_BASE + 65) },
	{ "shmget", (__NR_SYSCALL_BASE + 28) },
	{ "shutdown", (__NR_SYSCALL_BASE + 47) },
	{ "sigaction", __PNR_sigaction },
	{ "sigaltstack", (__NR_SYSCALL_BASE + 129) },
	{ "signal", __PNR_signal },
	{ "signalfd", (__NR_SYSCALL_BASE + 280) },
	{ "signalfd4", (__NR_SYSCALL_BASE + 287) },
	{ "sigpending", __PNR_sigpending },
	{ "sigprocmask", __PNR_sigprocmask },
	{ "sigreturn", __PNR_sigreturn },
	{ "sigsuspend", __PNR_sigsuspend },
	{ "socket", (__NR_SYSCALL_BASE + 40) },
	{ "socketcall", __PNR_socketcall },
	{ "socketpair", (__NR_SYSCALL_BASE + 52) },
	{ "splice", (__NR_SYSCALL_BASE + 267) },
	{ "ssetmask", __PNR_ssetmask },
	{ "stat", (__NR_SYSCALL_BASE + 4) },
	{ "stat64", __PNR_stat64 },
	{ "statfs", (__NR_SYSCALL_BASE + 134) },
	{ "statfs64", (__NR_SYSCALL_BASE + 217) },
	{ "stime", __PNR_stime },
	{ "stty", __PNR_stty },
	{ "swapoff", (__NR_SYSCALL_BASE + 163) },
	{ "swapon", (__NR_SYSCALL_BASE + 162) },
	{ "symlink", (__NR_SYSCALL_BASE + 86) },
	{ "symlinkat", (__NR_SYSCALL_BASE + 260) },
	{ "sync", (__NR_SYSCALL_BASE + 157) },
	{ "sync_file_range", (__NR_SYSCALL_BASE + 268) },
	{ "sync_file_range2", __PNR_sync_file_range2 },
	{ "syncfs", (__NR_SYSCALL_BASE + 306) },
	{ "syscall", __PNR_syscall },
	{ "sysfs", (__NR_SYSCALL_BASE + 136) },
	{ "sysinfo", (__NR_SYSCALL_BASE + 97) },
	{ "syslog", (__NR_SYSCALL_BASE + 101) },
	{ "sysmips", (__NR_SYSCALL_BASE + 199) },
	{ "tee", (__NR_SYSCALL_BASE + 269) },
	{ "tgkill", (__NR_SYSCALL_BASE + 229) },
	{ "time", __PNR_time },
	{ "timer_create", (__NR_SYSCALL_BASE + 220) },
	{ "timer_delete", (__NR_SYSCALL_BASE + 224) },
	{ "timer_getoverrun", (__NR_SYSCALL_BASE + 223) },
	{ "timer_gettime", (__NR_SYSCALL_BASE + 222) },
	{ "timer_settime", (__NR_SYSCALL_BASE + 221) },
	{ "timerfd", (__NR_SYSCALL_BASE + 281) },
	{ "timerfd_create", (__NR_SYSCALL_BASE + 284) },
	{ "timerfd_gettime", (__NR_SYSCALL_BASE + 285) },
	{ "timerfd_settime", (__NR_SYSCALL_BASE + 286) },
	{ "times", (__NR_SYSCALL_BASE + 98) },
	{ "tkill", (__NR_SYSCALL_BASE + 192) },
	{ "truncate", (__NR_SYSCALL_BASE + 74) },
	{ "truncate64", __PNR_truncate64 },
	{ "tuxcall", __PNR_tuxcall },
	{ "ugetrlimit", __PNR_ugetrlimit },
	{ "ulimit", __PNR_ulimit },
	{ "umask", (__NR_SYSCALL_BASE + 93) },
	{ "umount", __PNR_umount },
	{ "umount2", (__NR_SYSCALL_BASE + 161) },
	{ "uname", (__NR_SYSCALL_BASE + 61) },
	{ "unlink", (__NR_SYSCALL_BASE + 85) },
	{ "unlinkat", (__NR_SYSCALL_BASE + 257) },
	{ "unshare", (__NR_SYSCALL_BASE + 266) },
	{ "uselib", __PNR_uselib },
	{ "usr26", __PNR_usr26 },
	{ "usr32", __PNR_usr32 },
	{ "ustat", (__NR_SYSCALL_BASE + 133) },
	{ "utime", (__NR_SYSCALL_BASE + 130) },
	{ "utimensat", (__NR_SYSCALL_BASE + 279) },
	{ "utimes", (__NR_SYSCALL_BASE + 230) },
	{ "vfork", __PNR_vfork },
	{ "vhangup", (__NR_SYSCALL_BASE + 150) },
	{ "vm86", __PNR_vm86 },
	{ "vm86old", __PNR_vm86old },
	{ "vmsplice", (__NR_SYSCALL_BASE + 270) },
	{ "vserver", (__NR_SYSCALL_BASE + 240) },
	{ "wait4", (__NR_SYSCALL_BASE + 59) },
	{ "waitid", (__NR_SYSCALL_BASE + 241) },
	{ "waitpid", __PNR_waitpid },
	{ "write", (__NR_SYSCALL_BASE + 1) },
	{ "writev", (__NR_SYSCALL_BASE + 19) },
	{ NULL, __NR_SCMP_ERROR },
};

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int mips64n32_syscall_resolve_name(const char *name)
{
	unsigned int iter;
	const struct arch_syscall_def *table = mips64n32_syscall_table;

	/* XXX - plenty of room for future improvement here */
	for (iter = 0; table[iter].name != NULL; iter++) {
		if (strcmp(name, table[iter].name) == 0)
			return table[iter].num;
	}

	return __NR_SCMP_ERROR;
}

/**
 * Resolve a syscall number to a name
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *mips64n32_syscall_resolve_num(int num)
{
	unsigned int iter;
	const struct arch_syscall_def *table = mips64n32_syscall_table;

	/* XXX - plenty of room for future improvement here */
	for (iter = 0; table[iter].num != __NR_SCMP_ERROR; iter++) {
		if (num == table[iter].num)
			return table[iter].name;
	}

	return NULL;
}

/**
 * Iterate through the syscall table and return the syscall name
 * @param spot the offset into the syscall table
 *
 * Return the syscall name at position @spot or NULL on failure.  This function
 * should only ever be used internally by libseccomp.
 *
 */
const char *mips64n32_syscall_iterate_name(unsigned int spot)
{
	/* XXX - no safety checks here */
	return mips64n32_syscall_table[spot].name;
}