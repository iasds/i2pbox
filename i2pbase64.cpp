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

// libFuzzer defines FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION; suppress the
// per-parse error chatter while fuzzing.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define I2PBOX_ERR(msg) ((void)0)
#else
#define I2PBOX_ERR(msg) (std::cerr << msg << std::endl)
#endif

static int printHelp(const char * exe, int exitcode)
{
	std::cout << "usage: " << exe << " [-d] [filename]" << std::endl;
	return exitcode;
}

// Pure base64 decode: strips CR/LF, validates the alphabet and padding, then
// decodes into out. Returns 0 on success, -1 on invalid input. This is the
// single implementation used by the tool and the fuzz harness.
int decode_base64_string(const std::string & input, std::vector<uint8_t> & out)
{
    constexpr size_t MAXSIZE = 16 * 1024 * 1024;
    if (input.size() > MAXSIZE) {
        I2PBOX_ERR("input too large (max 16 MiB)");
        return -1;
    }
    if (input.empty())
        return 0;

    std::string cleaned;
    cleaned.reserve(input.size());
    for (char ch : input)
        if (ch != '\r' && ch != '\n')
            cleaned.push_back(ch);

    for (size_t i = 0; i < cleaned.size(); ++i) {
        char ch = cleaned[i];
        if (i2p::data::IsBase64(ch))
            continue;
        if (ch == '=') {
            if (cleaned.find_first_not_of('=', i) != std::string::npos) {
                I2PBOX_ERR("invalid base64 padding at position " << i);
                return -1;
            }
            break;
        }
        I2PBOX_ERR("invalid base64 character at position " << i);
        return -1;
    }

    out.resize(cleaned.size());
    size_t outsz = i2p::data::Base64ToByteStream(cleaned, out.data(), out.size());
    if (!outsz) {
        I2PBOX_ERR("invalid base64 input");
        return -1;
    }
    out.resize(outsz);
    return 0;
}

int operate_b64_decode(int infile, int outfile) {
    constexpr size_t BUFFSZ = 16384;
    std::string input;
    char inbuf[BUFFSZ];
    ssize_t sz;
    while ((sz = read(infile, inbuf, sizeof(inbuf))) > 0) {
        input.append(inbuf, sz);
    }
    if (sz < 0) {
        perror("read");
        return -1;
    }
    std::vector<uint8_t> outbuf;
    if (decode_base64_string(input, outbuf) != 0)
        return -1;
    if (outbuf.empty())
        return 0;
    if (write(outfile, outbuf.data(), outbuf.size()) < 0) {
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
