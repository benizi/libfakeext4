#define _GNU_SOURCE
#include <dlfcn.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <sys/statfs.h>
#include <unistd.h>

/* debugging print functions (no-ops unless `DEBUG` is defined) */
#ifdef DEBUG
#include <stdio.h>
#define dprintf(FMT,ARG) {if (dbg) fprintf(stderr, FMT, ARG);}
#else
#define dprintf(FMT,ARG) /* FMT, ARG */
#endif
#define dprint(STR) dprintf("%s", STR)

/* function types for the functions we'll override */
typedef int (*statfs_ptr)(const char *path, struct statfs *buf);
typedef int (*fstatfs_ptr)(int fd, struct statfs *buf);

/* store the original functions */
static statfs_ptr o_statfs;
static fstatfs_ptr o_fstatfs;

/* initialization */
static int inited = 0;
static int dbg = 0;
static void _fakeext4_init() {
  if (inited) return;
  o_statfs = (statfs_ptr)dlsym(RTLD_NEXT, "statfs");
  o_fstatfs = (fstatfs_ptr)dlsym(RTLD_NEXT, "fstatfs");
  dbg = getenv("DEBUG_FAKE_EXT4") != NULL;
  inited++;
}

/* override the `f_type` field if the call was successful */
static int fix_f_type(int ret, struct statfs *buf) {
  if (ret == 0 && buf != NULL) {
    buf->f_type = EXT4_SUPER_MAGIC;
    dprint(" MODIFIED");
  }
  dprint("\n");
  return ret;
}

/* override statfs */
int statfs(const char *path, struct statfs *buf) {
  _fakeext4_init();
  dprintf("statfs(%s)", path);
  return fix_f_type(o_statfs(path, buf), buf);
}

/* override fstatfs */
int fstatfs(int fd, struct statfs *buf) {
  _fakeext4_init();
  dprintf("fstatfs(%d)", fd);
  return fix_f_type(o_fstatfs(fd, buf), buf);
}
