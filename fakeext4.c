#include <errno.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/statfs.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

/* Print a message and exit with a failing status */
#define DIE(FMT, ARG) { fprintf(stderr, FMT "\n", ARG); exit(EXIT_FAILURE); }
/* Exit with an error message, looking up details via `errno` */
#define ERR(MSG) DIE(MSG ": %s", strerror(errno))

/* Debug printing functions.
 *
 * Always disabled when `NDEBUG` is defined at compile-time.
 *
 * `DEBUG_FAKE_EXT4=all` sets the level to 2.
 * Any other non-empty `$DEBUG_FAKE_EXT4` sets the "level" to 1.
 */
#ifdef NDEBUG
#define debug_log(LEV,FMT,ARG) /* LEV, FMT, ARG */
#else
#define debug_log(LEV,FMT,ARG) { \
  if (debug_level >= LEV) fprintf(stderr, FMT "\n", ARG); \
}
#endif
#define dbg_verbose(FMT,ARG) debug_log(2, FMT, ARG)
#define dbg_print(FMT,ARG) debug_log(1, FMT, ARG)

/* Hash table for keeping track of pids with outstanding syscalls.
 *
 * Hash function is just the pid mod 4096.
 * Buckets are linked lists.
 */

#define N_BUCKETS 4096
#define HASH(ARG) ARG % N_BUCKETS

/* States a pid can be in */
#define NOT_WAITING 0
#define WAITING_TO_IGNORE 1
#define WAITING_TO_MODIFY 2

typedef struct waitlist *waitlist_ptr;
typedef struct waitnode *waitnode_ptr;

/* Node is a pid + a value */
struct waitnode {
  pid_t pid;
  char val;
};

/* List is a node + the next list */
struct waitlist {
  waitnode_ptr node;
  waitlist_ptr next;
};

static void check_exit(int state);
static pid_t check_wait(pid_t kid, int *state);
static char dbg_wait_status(pid_t pid, int syscall_nr);
static char get_wait_status(pid_t pid);
static void modify_f_type(pid_t pid);
static char next_wait_status(char wait_status, int syscall_nr);
static void set_wait_status(pid_t pid, char val);

/* Array of buckets for tracking the wait status of descendant processes */
static struct waitlist waiting[N_BUCKETS];

/* Level of debug output, if enabled. */
static int debug_level;

/* Check by pid to see if we're waiting on a syscall to return. */
static char get_wait_status(pid_t pid) {
  waitlist_ptr bucket = &waiting[HASH(pid)];
  while (bucket != NULL && bucket->node != NULL) {
    if (bucket->node->pid == pid)
      return bucket->node->val;
    bucket = bucket->next;
  }
  return 0;
}

/* Record the action to take when syscall returns, or that we're not waiting */
static void set_wait_status(pid_t pid, char val) {
  waitlist_ptr bucket = &waiting[HASH(pid)];
  while (bucket != NULL) {
    if (bucket->node == NULL) {
      bucket->node = (waitnode_ptr)malloc(sizeof(struct waitnode));
      if (bucket->node == NULL) ERR("malloc waitnode");
      bucket->node->pid = pid;
      bucket->node->val = val;
      bucket->next = (waitlist_ptr)malloc(sizeof(struct waitlist));
      if (bucket->next == NULL) ERR("malloc waitlist");
      return;
    }
    if (bucket->node->pid == pid) {
      bucket->node->val = val;
      return;
    }
    bucket = bucket->next;
  }
}

static void check_exit(int state) {
  if (!WIFEXITED(state)) return;
  dbg_print("WIFEXITED(%d)", state);
  exit(WEXITSTATUS(state));
}

/* Boilerplate for ignoring a PTRACE_EVENT_ stop. */
#define IGNORE(EVT) if ((*state) >> 8 == (SIGTRAP | (EVT << 8))) { \
  dbg_print("IGNORING " #EVT " in %d", pid); \
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL); \
  continue; \
}

/* Wait for a pid.
 * If it's the original child, check for an exit.
 * If it's a PTRACE_EVENT we're expecting, ignore it and loop.
 */
static pid_t check_wait(pid_t kid, int *state) {
  pid_t pid;
  for (;;) {
    pid = waitpid(-1, state, 0);
    dbg_verbose("waitpid(-1, %d, 0)", *state);
    dbg_verbose("waitpid(-1, state, 0) -> %d", pid);
    dbg_verbose("  tracer pid = %d", getpid());
    dbg_verbose("  original kid = %d", kid);
    if (pid == kid) check_exit(*state);
    IGNORE(PTRACE_EVENT_CLONE);
    IGNORE(PTRACE_EVENT_EXEC);
    IGNORE(PTRACE_EVENT_EXIT);
    IGNORE(PTRACE_EVENT_FORK);
    IGNORE(PTRACE_EVENT_STOP);
    IGNORE(PTRACE_EVENT_VFORK);
    IGNORE(PTRACE_EVENT_VFORK_DONE);
    break;
  }
  return pid;
}

/* X86_64 syscalls:
 * entry: call number in rax
 * args in rdi, rsi, rdx, r10, r8, r9
 * exit: ret val in rax
 */

/* Modify the value of the `f_type` field of a returned `struct statfs *`. */
static void modify_f_type(pid_t pid) {
  struct statfs *buf;
  struct user_regs_struct regs;
  long orig_type, *f_type_addr;

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  /* don't modify statfs values if syscall returned non-zero status */
  dbg_verbose("call returned %d", regs.rax);
  if (regs.rax != 0) return;


  buf = (struct statfs *)regs.rsi;
  /* don't modify statfs values if pointer is null */
  if (buf == NULL) return;
  dbg_verbose("buf != NULL: %p", buf);

  f_type_addr = (long *)(buf + offsetof(struct statfs, f_type));
  orig_type = ptrace(PTRACE_PEEKTEXT, pid, f_type_addr, NULL);
  dbg_print("buf->f_type = %ld", orig_type);
  ptrace(PTRACE_POKETEXT, pid, f_type_addr, EXT4_SUPER_MAGIC);
  dbg_print("  modified -> %ld", EXT4_SUPER_MAGIC);
}

/* Fetch current wait status with debugging info */
static char dbg_wait_status(pid_t pid, int syscall_nr) {
  char wait_status = get_wait_status(pid);
  dbg_verbose("get_wait_status(%d)", pid);
  dbg_verbose("  -> %d", wait_status);
  switch (wait_status) {
    case WAITING_TO_MODIFY:
      dbg_print("INTERCEPTED SYSCALL %ld RETURNED", syscall_nr);
      break;
    case WAITING_TO_IGNORE:
      dbg_verbose("IGNORING SYSCALL %ld", syscall_nr);
      break;
  }
  return wait_status;
}

/* Return the next wait status based on the current state and syscall number */
static char next_wait_status(char wait_status, int syscall_nr) {
  switch (wait_status) {
    case WAITING_TO_MODIFY:
    case WAITING_TO_IGNORE:
      return NOT_WAITING;
  }

  switch (syscall_nr) {
    case __NR_fstatfs:
    case __NR_statfs:
      dbg_print("WILL INTERCEPT SYSCALL %ld", syscall_nr);
      return WAITING_TO_MODIFY;
  }

  dbg_verbose("WILL IGNORE SYSCALL %ld", syscall_nr);
  return WAITING_TO_IGNORE;
}

int main(int argc, char **argv) {
  pid_t kid, pid;
  char wait_status, *debug_env;
  int state, syscall_nr;

  if (argc < 2) DIE("Usage: %s program [args]", argv[0]);

  debug_env = getenv("DEBUG_FAKE_EXT4");
  if (debug_env == NULL) debug_level = 0;
  else if (strncmp(debug_env, "all", 3)) debug_level = 1;
  else debug_level = 2;

  /* Run the rest of the cmd args as a PTRACE-able subprocess */
  kid = fork();
  if (kid == -1) ERR("Failed to fork");
  if (!kid) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(argv[1], argv + 1);
    ERR("Failed to run subprogram");
  }

  /* Wait for the PTRACE_TRACEME */
  waitpid(kid, &state, 0);

  /* Trace all subprocesses of the first spawned process */
  ptrace(PTRACE_SETOPTIONS, kid, 0, PTRACE_O_EXITKILL
      | PTRACE_O_TRACESYSGOOD
      | PTRACE_O_TRACECLONE
      | PTRACE_O_TRACEFORK
      | PTRACE_O_TRACEVFORK);

  /* Loop, waiting for syscalls from descendant processes */
  pid = kid;
  for (;;) {
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    pid = check_wait(kid, &state);
    dbg_verbose("STATE = %d", state);

    /* continue unless this was a ptrace syscall-stop */
    if (!(WIFSTOPPED(state) && (WSTOPSIG(state) & 0x80))) continue;
    dbg_verbose("%s", "WIFSTOPPED(state) && (WSTOPSIG(state) & 0x80)");
    dbg_verbose("pid = %d", pid);

    /* Get the current syscall's number */
    syscall_nr = ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX * sizeof(long), NULL);

    /* Check to see if we're waiting to act on this syscall's return */
    wait_status = dbg_wait_status(pid, syscall_nr);

    /* Modify the return value if necessary */
    if (wait_status == WAITING_TO_MODIFY)
      modify_f_type(pid);

    /* Update the state for the next syscall for this pid */
    set_wait_status(pid, next_wait_status(wait_status, syscall_nr));
  }

  return 1;
}
