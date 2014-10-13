/*
    sandbox.c -- Use Linux namespaces and seccomp to sandbox a process.
    Copyright (C) 2014 Patrick Joseph Donnelly

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/mount.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define error(s) do { perror(s); exit(EXIT_FAILURE); } while (0)
#define CATCH(s) do { if (s) { fprintf(stderr, "[%s:%d] error: %d (%s)\n", __FILE__, __LINE__, s, strerror(-s)); exit(EXIT_FAILURE); } } while (0)

static const uid_t unobody = 10000;
static const gid_t gnobody = 10000;

struct context {
    int argc;
    char **argv;
    uid_t uid;
    gid_t gid;
    char sandbox[PATH_MAX];
};

static int filter (void)
{
    static const int whitelist[] = {
        SCMP_SYS(brk),
        SCMP_SYS(close),
        SCMP_SYS(clone),
        SCMP_SYS(execve),
        SCMP_SYS(exit),
        SCMP_SYS(exit_group),
        SCMP_SYS(fork),
        SCMP_SYS(getpgid),
        SCMP_SYS(getpid),
        SCMP_SYS(getppid),
        SCMP_SYS(getsid),
        SCMP_SYS(mmap),
        SCMP_SYS(mkdir),
        SCMP_SYS(mkdirat),
        SCMP_SYS(openat),
        SCMP_SYS(open),
        SCMP_SYS(read),
        SCMP_SYS(setsid),
        SCMP_SYS(stat),
        SCMP_SYS(wait4),
        SCMP_SYS(write),
    };
    static const struct {
        int syscall;
        unsigned int count;
        struct scmp_arg_cmp a0, a1, a2, a3, a4, a5, a6;
    } blacklist[] = {
        {SCMP_SYS(chroot)},
        {SCMP_SYS(mount)},
        {SCMP_SYS(prctl), 1, SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP)},
        /* Now one would think we'd block ptrace but because we don't allow
         * changing the seccomp filter, a tracer cannot enable system calls we
         * blacklist via SCMP_ACT_TRACE. */
        {SCMP_SYS(setuid)},
        {SCMP_SYS(setgid)},
        {SCMP_SYS(umount)},
        {SCMP_SYS(unshare)},
    };

    int i;
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (seccomp_arch_exist(ctx, SCMP_ARCH_X86) == 0) {
        fprintf(stderr, "SCMP_ARCH_X86 already loaded\n");
    } else {
        if (seccomp_arch_add(ctx, SCMP_ARCH_X86) == 0);
            fprintf(stderr, "SCMP_ARCH_X86 loaded\n");
    }
    if (seccomp_arch_exist(ctx, SCMP_ARCH_X86_64) == 0) {
        fprintf(stderr, "SCMP_ARCH_X86_64 already loaded\n");
    } else {
        if (seccomp_arch_add(ctx, SCMP_ARCH_X86_64) == 0);
            fprintf(stderr, "SCMP_ARCH_X86_64 loaded\n");
    }

    for (i = 0; i < sizeof(blacklist)/sizeof(blacklist[0]); i++)
        CATCH(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), blacklist[i].syscall, blacklist[i].count, blacklist[i].a0, blacklist[i].a1, blacklist[i].a2, blacklist[i].a3, blacklist[i].a4, blacklist[i].a5, blacklist[i].a6));
    //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
    //for (i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++)
        //CATCH(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, whitelist[i], 0));

    CATCH(seccomp_load(ctx));
    seccomp_release(ctx);
    assert(prctl(PR_SET_SECCOMP) == -1 && errno == ENOSYS);
    assert(prctl(PR_GET_SECCOMP) == 2);
}

static void closefds (void)
{
    int i;
    int n = sysconf(_SC_OPEN_MAX);
    for (i = 0; i < n; i++)
        close(i);
    i = open("/dev/null", O_RDWR);
    if (i == -1)
        error("open /dev/null");
    if (dup2(i, STDIN_FILENO) == -1);
        error("dup2");
    if (dup2(i, STDOUT_FILENO) == -1);
        error("dup2");
    if (dup2(i, STDERR_FILENO) == -1);
        error("dup2");
    if (close(i) == -1)
        error("close");
}

static int become (uid_t ouid, gid_t ogid, uid_t uid, gid_t gid)
{
    FILE *file;

    fprintf(stderr, "becoming %d\n", (int)uid);

    /* unshare(CLONE_NEWUSER) is only permitted if we have full capabilities */
    if (uid) {
        if (unshare(CLONE_NEWUSER) == -1)
            error("unshare");
    }

    file = fopen("/proc/self/uid_map", "w");
    if (!file)
        error("fopen");
    if (fprintf(file, "%d %d 1\n", (int)uid, (int)ouid) < 0)
        error("fprintf");;
    if (fclose(file) == EOF)
        error("fclose");

    file = fopen("/proc/self/gid_map", "w");
    if (!file)
        error("fopen");
    if (fprintf(file, "%d %d 1\n", (int)gid, (int)ogid) < 0)
        error("fprintf");;
    if (fclose(file) == EOF)
        error("fclose");

    if (setgroups(0, NULL) == -1)
        error("setgroups");
}

static void entersandbox (void)
{
    if (mkdir("root", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root", "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, NULL) == -1)
        error("mount root");

    symlink("usr/bin", "root/bin");

    if (mkdir("root/dev", 0) == -1)
        error("mkdir /dev");
    //if (mount(NULL, "root/dev", "devtmpfs", MS_NOEXEC|MS_NOSUID, NULL) == -1)
        //error("mount /dev");
    if (mount(NULL, "root/dev", "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, NULL) == -1)
        error("mount /dev");
    symlink("/proc/self/fd", "root/dev/fd");
    {
        int fd = open("root/dev/full", O_CREAT|O_TRUNC|O_WRONLY, 0);
        if (mount("/dev/full", "root/dev/full", NULL, MS_BIND, NULL) == -1)
            error("mount /dev/full");
        close(fd);
    }
    {
        int fd = open("root/dev/null", O_CREAT|O_TRUNC|O_WRONLY, 0);
        if (mount("/dev/null", "root/dev/null", NULL, MS_BIND, NULL) == -1)
            error("mount /dev/null");
        close(fd);
    }
    if (mkdir("root/dev/pts", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root/dev/pts", "devpts", MS_NOATIME|MS_NOEXEC|MS_NOSUID, "newinstance") == -1)
        error("mount /dev/pts");
    symlink("pts/ptmx", "root/dev/ptmx");
    {
        int fd = open("root/dev/random", O_CREAT|O_TRUNC|O_WRONLY, 0);
        if (mount("/dev/random", "root/dev/random", NULL, MS_BIND, NULL) == -1)
            error("mount /dev/random");
        close(fd);
    }
    if (mkdir("root/dev/shm", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root/dev/shm", "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, NULL) == -1)
        error("mount /dev/shm");
    symlink("/proc/self/fd/0", "root/dev/stdin");
    symlink("/proc/self/fd/1", "root/dev/stdout");
    symlink("/proc/self/fd/2", "root/dev/stderr");
    {
        int fd = open("root/dev/urandom", O_CREAT|O_TRUNC|O_WRONLY, 0);
        if (mount("/dev/urandom", "root/dev/urandom", NULL, MS_BIND, NULL) == -1)
            error("mount /dev/urandom");
        close(fd);
    }
    {
        int fd = open("root/dev/zero", O_CREAT|O_TRUNC|O_WRONLY, 0);
        if (mount("/dev/zero", "root/dev/zero", NULL, MS_BIND, NULL) == -1)
            error("mount /dev/zero");
        close(fd);
    }

    if (mkdir("root/etc", 0) == -1)
        error("mkdir");
    if (mount("/etc", "root/etc", NULL, MS_BIND|MS_RDONLY, NULL) == -1)
        error("mount /etc");
    {
        FILE *file = fopen("passwd", "w");
        if (!file)
            error("fopen");
        if (fprintf(file, "root:x:0:0:root:/root:/bin/sh\n") < 0)
            error("fprintf");;
        if (fprintf(file, "nobody:x:%d:%d:nobody:/home/nobody:/bin/sh\n", (int)unobody, (int)gnobody) < 0)
            error("fprintf");;
        if (fclose(file) == EOF)
            error("fclose");
    }
    if (mount("./passwd", "root/etc/passwd", NULL, MS_BIND|MS_RDONLY, NULL) == -1)
        error("mount /etc/passwd");

    if (mkdir("home", S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) == -1)
        error("mkdir");
    if (mkdir("home/nobody", S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) == -1)
        error("mkdir");
    if (mkdir("root/home", 0) == -1)
        error("mkdir");
    if (mount("./home", "root/home", NULL, MS_BIND, NULL) == -1)
        error("mount /home");

    if (symlink("usr/lib", "root/lib") == -1)
        error("symlink");
    if (symlink("usr/lib64", "root/lib64") == -1)
        error("symlink");

    if (mkdir("root/mnt", 0) == -1)
        error("mkdir");

    if (mkdir("root/proc", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root/proc", "proc", MS_NOATIME|MS_NODEV|MS_NOEXEC|MS_NOSUID, NULL) == -1)
        error("mount /proc");

    mkdir("root/sys", 0);
    //if (mount(NULL, "root/sys", "sysfs", MS_NOATIME|MS_NODEV|MS_NOEXEC|MS_NOSUID, NULL) == -1)
        //error("mount /sys");

    if (mkdir("root/root", S_IRWXU) == -1)
        error("mkdir");

    if (mkdir("root/run", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root/run", "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, NULL) == -1)
        error("mount /run");

    if (mkdir("root/tmp", 0) == -1)
        error("mkdir");
    if (mount(NULL, "root/tmp", "tmpfs", MS_NODEV|MS_NOSUID|MS_STRICTATIME, NULL) == -1)
        error("mount /tmp");

    if (mkdir("root/usr", 0) == -1)
        error("mkdir");
    if (mount("/usr", "root/usr", NULL, MS_BIND|MS_RDONLY, NULL) == -1)
        error("mount /usr");

    if (mkdir("read-only", S_IRWXU) == -1)
        error("mkdir");
    {
        int fd = open("read-only/bar", O_CREAT|O_WRONLY|O_TRUNC, 0644);
        write(fd, "hi\n", 3);
        close(fd);
    }
    close(open("root/home/nobody/foo", O_CREAT|O_EXCL|O_WRONLY, 0));
    if (mount("./read-only/bar", "root/home/nobody/foo", NULL, MS_BIND|MS_RDONLY, NULL) == -1)
        error("mount /home/nobody/foo");


    if (chdir("root") == -1)
        error("chdir root");
    if (mount(".", "/", NULL, MS_MOVE, NULL) == -1)
        error("mount /");
    if (chroot(".") == -1)
        error("chroot .");
    if (chdir("/") == -1)
        error("chdir /");

    if (mount("/", "/", NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NODEV, NULL) == -1)
        error("remount /");
    if (mount(NULL, "/dev", NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NODEV, NULL) == -1)
        error("remount /dev");
}

static int do_exec (void *ud)
{
    struct context *context = ud;

    if (setsid() == -1)
        error("setsid");
    assert(getpid() == 1);
    assert(getppid() == 0);
    assert(getpgid(0) == 1);
    assert(getsid(0) == 1);

    become(0, 0, unobody, gnobody);
    assert(getuid() == unobody && getgid() == gnobody);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        error("prctl");

    filter();

    fprintf(stderr, "i am %d\n", (int)getpid());
    if (fork() > 0)
        {while (wait(NULL) >0 ) ; exit(0);}
    fprintf(stderr, "i am %d\n", (int)getpid());
    if (fork() > 0)
        exit(0);
    fprintf(stderr, "i am %d\n", (int)getpid());

    if (context->argc <= 0) {
        if (execlp("bash", "bash", "echo", "hi", NULL) == -1);
            error("execlp");
    } else {
        if (execvp(context->argv[0], context->argv) == -1);
            error("execlp");
    }
}

static void test (int a) {}
static int do_starter (void *ud)
{
    struct context *context = ud;
    char stack[1<<14];
    signal(SIGCHLD ,test);

    if (setsid() == -1)
        error("setsid");
    assert(getpid() == 1);
    assert(getppid() == 0);
    assert(getpgid(0) == 1);
    assert(getsid(0) == 1);

    chdir(context->sandbox);
    if (0) closefds();

    become(context->uid, context->gid, 0, 0);
    entersandbox();

    pid_t pid = clone(do_exec, stack, CLONE_NEWIPC|CLONE_NEWPID|SIGCHLD, &context);
    if (pid == -1)
        error("clone");
    fprintf(stderr, "forked %d\n", pid);

    while (1) {
        int status;
        pid_t child = wait(&status);
        fprintf(stderr, "wait = %d\n",child);
        if (child == -1) {
            perror("wait");
            break;
        } else {
            fprintf(stderr, "child %d finished\n", (int)child);
            system("ls -lhad /proc/[0-9]*; grep Pid /proc/[0-9]*/status");
        }
    }
    return 0;
}

int main (int argc, char *argv[])
{
    char stack[1<<16];
    struct context context = {argc-1, argv+1, getuid(), getgid(), "/tmp/tmp.XXXXXX"};

    if (mkdtemp(context.sandbox) == NULL)
        error("mkdtemp");
    fprintf(stderr, "created sandbox `%s'\n", context.sandbox);

    if (0) {
        /* XXX ideally this will let us use tools like screen? */
        int master = posix_openpt(O_RDWR);
        if (master == -1)
            error("posix_openpt");
        fprintf(stderr, "%d\n", master);
        if (grantpt(master) == -1)
            error("grantpt");
        if (unlockpt(master) == -1)
            error("grantpt");
        /* ptsname */
        /* need to pipe output to terminal above? */
    }

    pid_t pid = clone(do_starter, stack+sizeof(stack), CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUSER|SIGCHLD, &context);
    if (pid == -1)
        error("clone");
    fprintf(stderr, "forked %d\n", pid);

    {
        int status;
        pid_t child = waitpid(pid, &status, 0);
        if (child == -1)
            error("wait");
        fprintf(stderr, "starter %d exited\n", child);
    }

    fprintf(stderr, "deleting sandbox `%s'\n", context.sandbox);
    return execl("/bin/rm", "rm", "-rf", context.sandbox, NULL);
}
