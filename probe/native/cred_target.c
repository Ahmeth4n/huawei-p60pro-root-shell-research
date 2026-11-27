#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uid_t uid = getuid();
    gid_t gid = getgid();
    int uid_result = setresuid(uid, uid, uid);
    int gid_result = setresgid(gid, gid, gid);
    printf("pid=%ld uid=%ld gid=%ld setresuid=%d setresgid=%d errno=%d\n",
           (long)getpid(), (long)getuid(), (long)getgid(),
           uid_result, gid_result, errno);
    printf("waiting for one input byte; 's' requests a shell, any other byte exits\n");
    char command = 0;
    if (read(STDIN_FILENO, &command, 1) != 1) return 1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    syscall(__NR_capget, &header, data);
    printf("after: uid=%ld euid=%ld gid=%ld egid=%ld cap_eff=%08x:%08x\n",
           (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid(),
           data[1].effective, data[0].effective);
    if (command == 's') {
        char *const argv[] = {"sh", NULL};
        execv("/system/bin/sh", argv);
        perror("execv sh");
        return 2;
    }
    return 0;
}
