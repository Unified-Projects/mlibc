#include <unified/syscall.h>

#include <asm/ioctls.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>

#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

namespace mlibc{

typedef struct {
	dev_t st_dev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	uid_t st_gid;
	dev_t st_rdev;
	off_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
} unified_stat_t;

int sys_write(int fd, const void* buffer, size_t count, ssize_t* written){
	long ret = syscall(SYS_WRITE, fd, (uintptr_t)buffer, count);

	if(ret < 0)
		return -ret;

	*written = ret;
	return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	long ret = syscall(SYS_READ, fd, (uintptr_t)buf, count);

	if(ret < 0){
		*bytes_read = 0;
		return -ret;
	}

	*bytes_read = ret;
	return 0;
}

int sys_pwrite(int fd, const void* buffer, size_t count, off_t off, ssize_t* written){
	int ret = syscall(SYS_PWRITE, fd, (uintptr_t)buffer, count, 0, off);


	if(ret < 0){
		return -ret;
	}

	*written = ret;
	return 0;
}

int sys_pread(int fd, void *buf, size_t count, off_t off, ssize_t *bytes_read) {
	int ret = syscall(SYS_PREAD, fd, (uintptr_t)buf, count, 0, off);

	if(ret < 0){
		return -ret;
	}

	*bytes_read = ret;
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	long ret = syscall(SYS_LSEEK, fd, offset, whence);

	if(ret < 0){
		return -ret;
	}

	*new_offset = ret;
	return 0;
}


int sys_open(const char* filename, int flags, mode_t mode, int* fd){
	long ret = syscall(SYS_OPEN, (uintptr_t)filename, flags);

	if(ret < 0)
		return -ret;

	*fd = ret;

	return 0;
}

int sys_close(int fd){
	syscall(SYS_CLOSE, fd);
	return 0;
}

int sys_access(const char* filename, int mode){
	int fd;
	if(int e = sys_open(filename, O_RDONLY, 0, &fd)){
		return e;
	}

	sys_close(fd);
	return 0;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf){
	long ret = 0;

	unified_stat_t unifiedStat;
	switch(fsfdt){
		case fsfd_target::fd:
			ret = syscall(SYS_FSTAT, &unifiedStat, fd);
			break;
		case fsfd_target::path:
			ret = syscall(SYS_STAT, &unifiedStat, path);
			break;
		case fsfd_target::fd_path:
			ret = syscall(SYS_FSTATAT, fd, (uintptr_t)path, (uintptr_t)&unifiedStat, flags);
			break;
		default:
			mlibc::infoLogger() << "mlibc: stat: Unknown fsfd_target: " << (int)fsfdt << frg::endlog;
			return ENOSYS;
	}

	statbuf->st_dev = unifiedStat.st_dev;
	statbuf->st_ino = unifiedStat.st_ino;
	statbuf->st_mode = unifiedStat.st_mode;
	statbuf->st_nlink = unifiedStat.st_nlink;
	statbuf->st_uid = unifiedStat.st_uid;
	statbuf->st_gid = unifiedStat.st_gid;
	statbuf->st_rdev = unifiedStat.st_rdev;
	statbuf->st_size = unifiedStat.st_size;
	statbuf->st_blksize = unifiedStat.st_blksize;
	statbuf->st_blocks = unifiedStat.st_blocks;

	return -ret;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result){
	long ret = syscall(SYS_IOCTL, fd, request, arg, result);

	if(ret < 0)
		return -ret;

	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events){
	long ret = syscall(SYS_POLL, fds, count, timeout);

	if(ret < 0){
		return -ret;
	}

	*num_events = ret;

	return 0;
}

int sys_mkdir(const char* path, mode_t){
	long ret = syscall(SYS_MKDIR, path);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int sys_rmdir(const char* path){
	long ret = syscall(SYS_RMDIR, path);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int sys_link(const char* srcpath, const char* destpath){
	long ret = syscall(SYS_LINK, srcpath, destpath);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int sys_unlinkat(int fd, const char *path, int flags) {
	long ret = syscall(SYS_UNLINK, fd, path, flags);

	if(ret < 0) {
		return -ret;
	}

	return 0;
}

typedef struct unified_dirent {
	uint32_t inode; // Inode number
	uint32_t type;
	char name[NAME_MAX]; // Filename
} unified_dirent_t;

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read)
{
    unified_dirent_t unifiedDirent;
    long ret = syscall(SYS_READDIR_NEXT, handle, &unifiedDirent);

    if (ret < 0) {
        // End of directory?
        if (ret == -ENOENT) {
            *bytes_read = 0;
            return 0;  // EOF
        }
        return -ret;  // real error
    }
    if (ret == 0) {
        // No entry read
        *bytes_read = 0;
        return 0;
    }
    // ret > 0: one entry read
    struct dirent *dir = (struct dirent *)buffer;
    // Copy name safely
    strncpy(dir->d_name, unifiedDirent.name, NAME_MAX - 1);
    dir->d_name[NAME_MAX - 1] = '\0';
    dir->d_ino   = unifiedDirent.inode;
    dir->d_off   = 0;
    dir->d_reclen = sizeof(struct dirent);
    dir->d_type  = unifiedDirent.type;

    *bytes_read = sizeof(struct dirent);
    return 0;
}

int sys_open_dir(const char* path, int* handle){
	return sys_open(path, O_DIRECTORY, 0, handle);
}

int sys_rename(const char* path, const char* new_path){
	return -syscall(SYS_RENAME, path, new_path);
}

int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length){
	long ret = syscall(SYS_READLINK, path, buffer, max_size);
	if(ret < 0){
		return -ret;
	}

	*length = ret;
	return 0;
}

int sys_dup(int fd, int flags, int* newfd){
	int ret = syscall(SYS_DUP, fd, flags, -1);
	if(ret < 0){
		return -ret;
	}

	*newfd = ret;
	return 0;
}

int sys_dup2(int fd, int flags, int newfd){
	int ret = syscall(SYS_DUP, fd, flags, newfd);
	if(ret < 0){
		return -ret;
	}

	return 0;
}

int sys_fcntl(int fd, int request, va_list args, int* result){
	if(request == F_DUPFD){
		return sys_dup(fd, 0, result);
	} else if (request == F_DUPFD_CLOEXEC) {
		return sys_dup(fd, O_CLOEXEC, result);
	} else if(request == F_GETFD){
		*result = 0;
		return 0;
	} else if(request == F_SETFD){
		if(va_arg(args, int) & FD_CLOEXEC) {
			return sys_ioctl(fd, FIOCLEX, NULL, result);
		} else {
			return sys_ioctl(fd, FIONCLEX, NULL, result);
		}
	} else if(request == F_GETFL){
		int ret = syscall(SYS_GET_FILE_STATUS_FLAGS, fd);
		if(ret < 0){
			return -ret;
		}

		*result = ret;
		return 0;
	} else if(request == F_SETFL){
		int ret = syscall(SYS_SET_FILE_STATUS_FLAGS, fd, va_arg(args, int));
		return -ret;
	} else if(request == F_GETPIPE_SZ) {
		// Return a default pipe buffer size (64 KiB)
		*result = 65536;
		return 0;
	} else if(request == F_SETPIPE_SZ) {
		// Ignore attempts to change pipe size; return the current size
		int newSize = va_arg(args, int);
		(void)newSize;
		*result = 65536;
		return 0;
	} else {
		infoLogger() << "mlibc: sys_fcntl unsupported request (" << request << ")" << frg::endlog;
		return EINVAL;
	}
}

int sys_pselect(int nfds, fd_set* readfds, fd_set* writefds,
	fd_set *exceptfds, const struct timespec* timeout, const sigset_t* sigmask, int *num_events){
	int ret = syscall(SYS_SELECT, nfds, readfds, writefds, exceptfds, timeout);
	if(ret < 0){
		return -ret;
	}

	*num_events = ret;
	return 0;
}

int sys_chmod(const char *pathname, mode_t mode){
	int ret = syscall(SYS_CHMOD, pathname, mode);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int sys_pipe(int *fds, int flags){
	return -syscall(SYS_PIPE, fds, flags);
}

int sys_epoll_create(int flags, int *fd) {
	int ret = syscall(SYS_EPOLL_CREATE, flags);

	if(ret < 0){
		return -ret;
	}

	*fd = ret;

	return 0;
}

int sys_epoll_ctl(int epfd, int mode, int fd, struct epoll_event *ev) {
	int ret = syscall(SYS_EPOLL_CTL, epfd, mode, fd, ev);

	if(ret < 0) {
		return -ret;
	}

	return 0;
}

int sys_epoll_pwait(int epfd, struct epoll_event *ev, int n,
		int timeout, const sigset_t *sigmask, int *raised) {
	int ret = syscall(SYS_EPOLL_WAIT, epfd, ev, n, timeout, sigmask);

	if(ret < 0) {
		return -ret;
	}

	*raised = ret;

	return 0;
}

int sys_ttyname(int tty, char *buf, size_t size) {
	char path[PATH_MAX] = {"/dev/pts/"};

	struct stat stat;
	if(int e = sys_stat(fsfd_target::fd, tty, nullptr, 0, &stat)) {
		return e;
	}

	if(!S_ISCHR(stat.st_mode)) {
		return ENOTTY; // Not a char device, isn't a tty
	}

	if(sys_isatty(tty)) {
		return ENOTTY;
	}

	// Look for tty in /dev/pts
	int ptDir = open("/dev/pts", O_DIRECTORY);
	__ensure(ptDir >= 0);

	struct dirent dirent;
	size_t direntBytesRead;
	while(!sys_read_entries(ptDir, &dirent, sizeof(dirent), &direntBytesRead) && direntBytesRead) {
		// Compare the inodes
		if(dirent.d_ino == stat.st_ino) {
			__ensure(strlen(path) + strlen(dirent.d_name) < PATH_MAX);
			strcat(path, dirent.d_name);

			strncpy(buf, path, size);
			return 0;
		}
	}

	// Could not find corresponding TTY in /dev/pts
	return ENODEV;
}

int sys_fchdir(int fd) {
	return syscall(SYS_FCHDIR, fd);
}

int sys_fsync(int fd)
{
    long ret = syscall(SYS_FSYNC, fd);
    if (ret < 0) {
        return -ret;   // return positive errno
    }
    return 0;
}

void sys_sync()
{
    syscall(SYS_SYNC);
}

int sys_mount(const char *source, const char *target,
              const char *fstype, unsigned long flags, void *data)
{
    long ret = syscall(SYS_MOUNT,
                       (uintptr_t)source,
                       (uintptr_t)target,
                       (uintptr_t)fstype,
                       flags,
                       (uintptr_t)data);
    if (ret < 0) {
        return -ret;   // return positive errno
    }
    return 0;
}

#endif

}
