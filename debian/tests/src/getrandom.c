#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include <linux/random.h>

int main (void) {
    int ret;
    int buflen = 256;
    char buf[buflen];
    buf[0] = '\0';

    ret = syscall(SYS_getrandom, buf, buflen, 0);
    if (ret < 0) {
        printf("FAIL (error)\n");
        return ret;
    }
    if (ret == buflen) {
        printf("PASS\n");
        return 0;
    }
    printf("FAIL (short read: %i)\n", ret);
    return 1;

failure:
    errno = EIO;
    return -1;
}
