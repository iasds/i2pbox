#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <functional>
#include <cassert>
#include <algorithm>
#include <vector>
#include "Base.h"

const size_t BUFFSZ = 1024;

static int printHelp(const char * exe, int exitcode)
{
	std::cout << "usage: " << exe << " [-d] [filename]" << std::endl;
	return exitcode;
}

int operate_b64_decode(int infile, int outfile) {
    constexpr size_t BUFFSZ = 16384;
    constexpr size_t MAXSIZE = 16 * 1024 * 1024;
    std::string input;
    char inbuf[BUFFSZ];
    ssize_t sz;
    while ((sz = read(infile, inbuf, sizeof(inbuf))) > 0) {
        if (input.size() + static_cast<size_t>(sz) > MAXSIZE) {
            std::cerr << "input too large (max 16 MiB)" << std::endl;
            return -1;
        }
        input.append(inbuf, sz);
    }
    if (sz < 0) {
        perror("read");
        return -1;
    }
    if (input.empty())
        return 0;
    input.erase(std::remove_if(input.begin(), input.end(),
        [](char ch) { return ch == '\r' || ch == '\n'; }), input.end());
    for (size_t i = 0; i < input.size(); ++i) {
        char ch = input[i];
        if (i2p::data::IsBase64(ch))
            continue;
        if (ch == '=') {
            if (input.find_first_not_of('=', i) != std::string::npos) {
                std::cerr << "invalid base64 padding at position " << i << std::endl;
                return -1;
            }
            break;
        }
        std::cerr << "invalid base64 character at position " << i << std::endl;
        return -1;
    }
    std::vector<uint8_t> outbuf(input.size());
    size_t outsz = i2p::data::Base64ToByteStream(input, outbuf.data(), outbuf.size());
    if (!outsz) {
        std::cerr << "invalid base64 input" << std::endl;
        return -1;
    }
    if (write(outfile, outbuf.data(), outsz) < 0) {
        perror("write");
        return -1;
    }
    return 0;
}


int operate_b64_encode(int infile, int outfile) {
    constexpr size_t BUFFSZ = 4096;
    uint8_t inbuf[BUFFSZ*3];     
    //char outbuf[BUFFSZ*4];     
    ssize_t sz;
    while((sz = read(infile, inbuf, sizeof(inbuf))) > 0) {
        std::string out = i2p::data::ByteStreamToBase64(inbuf, sz);
        if (write(outfile, out.data(), out.size()) < 0) {
            perror("write");
            return -1;
        }
    }
    if (sz < 0) {
        perror("read");
        return -1;
    }
    return 0;
}

int tool_i2pbase64(int argc, char *argv[])
{
	int opt;
	bool decode = false;
	int infile = 0;
	while((opt = getopt(argc, argv, "dh")) != -1)
	{
		switch(opt)
		{
		case 'h':
			return printHelp(argv[0], 0);
		case 'd':
			decode = true;
			break;
		default:
			continue;
		}
	}

	if (argc - optind > 1)
	{
		return printHelp(argv[0], 1);
	}

	if (optind < argc)
	{
		infile = open(argv[optind], O_RDONLY);
		if(infile == -1) {
			perror(argv[optind]);
			return 1;
		}
	}
	int retcode = 0;
	if(decode)
	{
		retcode = operate_b64_decode(infile, 1);
	}
	else
	{
		retcode = operate_b64_encode(infile, 1);
	}
	if(infile > 0) close(infile);
	return retcode < 0 ? 1 : 0;
}
