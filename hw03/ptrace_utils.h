#include <sys/ptrace.h>
#include <unistd.h>

void ptrace_traceme() {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
}

void ptrace_cont(pid_t tracee) {
    ptrace(PTRACE_CONT, tracee, 0, 0);
}

void ptrace_singlestep(pid_t tracee) {
    ptrace(PTRACE_SINGLESTEP, tracee, 0, 0);
}

long ptrace_peektext(pid_t tracee, __uint64_t addr) {
    return ptrace(PTRACE_PEEKTEXT, tracee, addr, 0);
}

void ptrace_poketext(pid_t tracee, __uint64_t addr, long value) {
    ptrace(PTRACE_POKETEXT, tracee, addr, value);
}

void ptrace_getregs(pid_t tracee, struct user_regs_struct *regs) {
    ptrace(PTRACE_GETREGS, tracee, 0, regs);
}

void ptrace_setregs(pid_t tracee, struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, tracee, 0, regs);
}

void ptrace_syscall(pid_t tracee) {
    ptrace(PTRACE_SYSCALL, tracee, 0, 0);
}