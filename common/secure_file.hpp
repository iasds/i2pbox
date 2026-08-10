#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace i2pbox {

inline bool FileExists(const std::string& path) {
	struct stat st;
	return stat(path.c_str(), &st) == 0;
}

inline int OpenPrivateFile(const std::string& path) {
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef _WIN32
    flags |= O_BINARY;
    const int fd = _open(path.c_str(), flags, _S_IREAD | _S_IWRITE);
#else
    const int fd = open(path.c_str(), flags, S_IRUSR | S_IWUSR);
#endif
    if (fd < 0) return -1;

#ifndef _WIN32
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_nlink > 1) {
        close(fd);
        return -1;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        unlink(path.c_str());
        return -1;
    }
#endif
    return fd;
}

inline bool WritePrivateFile(const std::string& path, const uint8_t* data, size_t size) {
#ifndef _WIN32
    signal(SIGXFSZ, SIG_IGN);
#endif
    const int fd = OpenPrivateFile(path);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < size) {
#ifdef _WIN32
        const int result = _write(fd, data + written, static_cast<unsigned int>(size - written));
#else
        const ssize_t result = write(fd, data + written, size - written);
#endif
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) {
#ifdef _WIN32
            _close(fd);
            _unlink(path.c_str());
#else
            close(fd);
            unlink(path.c_str());
#endif
            return false;
        }
        written += static_cast<size_t>(result);
    }

#ifdef _WIN32
    return _close(fd) == 0;
#else
    const bool synced = fsync(fd) == 0;
    const bool closed = close(fd) == 0;
    if (!synced) unlink(path.c_str());
    return synced && closed;
#endif
}

} // namespace i2pbox
