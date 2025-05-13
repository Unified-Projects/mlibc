#include <asm/ioctls.h>
#include <sys/ioctl.h>

#include <errno.h>

#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

#include <stdio.h>

namespace mlibc {

int sys_isatty(int fd) {
	struct winsize ws;
	long ret = sys_ioctl(fd, TIOCGWINSZ, &ws, 0);

	if(!ret) return 0;

	return ENOTTY;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	if(int e = sys_isatty(fd))
		return e;

	int ret;
	sys_ioctl(fd, TCGETS, attr, &ret);

	if(ret)
		return -ret;

	return 0;
}

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) {
	if(int e = sys_isatty(fd))
		return e;

    int cmd;
    switch (optional_action) {
    case TCSANOW:
        cmd = TCSETS;
        break;
    case TCSADRAIN:
        cmd = TCSETSW;
        break;
    case TCSAFLUSH:
        cmd = TCSETSF;
        break;
    default:
        return EINVAL;
    }
    int ret;
    sys_ioctl(fd, cmd, const_cast<struct termios *>(attr), &ret);

	if(ret)
		return -ret;

	return 0;
}

int sys_ptsname(int fd, char *buffer, size_t length) {
	int index;
	if(int e = sys_ioctl(fd, TIOCGPTN, &index, NULL); e)
		return e;
	if((size_t)snprintf(buffer, length, "/dev/pts/%d", index) >= length) {
		return ERANGE;
	}
	return 0;
}

int sys_unlockpt(int fd) {
	int unlock = 0;

	if (int e = sys_ioctl(fd, TIOCSPTLCK, &unlock, NULL); e)
		return e;

	return 0;
}

int sys_setsid(pid_t *sid) {
    mlibc::infoLogger() << "mlibc: sys_setsid is a stub" << frg::endlog;
    return 0;
}
}