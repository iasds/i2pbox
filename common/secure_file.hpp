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
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace i2pbox {

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
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        return -1;
    }
#endif
    return fd;
}

inline bool WritePrivateFile(const std::string& path, const uint8_t* data, size_t size) {
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
#else
            close(fd);
#endif
            return false;
        }
        written += static_cast<size_t>(result);
    }

#ifdef _WIN32
    return _close(fd) == 0;
#else
    return close(fd) == 0;
#endif
}

} // namespace i2pbox
