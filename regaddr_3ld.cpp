#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include "Identity.h"
#include "Base.h"
#include <openssl/crypto.h>

static bool isValidName (const char * name)
{
	size_t len = 0;
	for (const char * p = name; *p; p++)
	{
		if (len >= 255) return false;
		const unsigned char c = *p;
		if ((c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '.' && c != '-' && c != '_')
			return false;
		len++;
	}
	return len > 0;
}

static void help ()
{
	std::cout << "Usage:" << std::endl;
	std::cout << "\tregaddr_3ld step1 privkey   address" << std::endl;
	std::cout << "\tregaddr_3ld step2 step1file oldprivkey oldaddress" << std::endl;
	std::cout << "\tregaddr_3ld step3 step2file privkey" << std::endl;
}

int tool_regaddr_3ld(int argc, char *argv[])
{
	if (argc < 3) {	help(); return -1;}
	std::string arg = argv[1];

	i2p::data::PrivateKeys keys;

	if (arg == "step1") {
		if (argc != 4) { help(); return -1; }
		if (!isValidName (argv[3]))
		{
			std::cerr << "Invalid address name " << argv[3] << std::endl;
			return 1;
		}
		std::ifstream s(argv[2], std::ifstream::binary);
		if (s.is_open ()) {
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			if (len == (size_t)-1 || len > 64*1024*1024) {
				std::cerr << "Failed to read keyfile " << argv[2] << std::endl;
				return 1;
			}
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			if (!s || static_cast<std::size_t>(s.gcount()) != len) {
				std::cerr << "short read on keyfile " << argv[2] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			if(keys.FromBuffer (buf, len)) {
				std::stringstream out;
				out << argv[3] << "="; // address
				out << keys.GetPublic ()->ToBase64 ();
				out << "#!action=addsubdomain";
				std::cout << out.str () << std::endl;
			} else {
				std::cout << "Failed to load keyfile " << argv[2] << std::endl;
				return 1;
			}
			OPENSSL_cleanse(buf, len);
			delete[] buf;
		}
	}
	else if (arg == "step2") {
		if (argc != 5) { help(); return -1; }
		std::ifstream t(argv[2]);
		std::ifstream s(argv[3], std::ifstream::binary);
		std::string regtxt;
		std::stringstream out;

		if (t.is_open ()) {
			while (getline (t, regtxt)) out << regtxt;
			t.close();
		} else {
			std::cout << "Failed to read file with STEP1 output" << std::endl;
			exit(1);
		}

		if (s.is_open ()) {
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			if (len == (size_t)-1 || len > 64*1024*1024) {
				std::cerr << "Failed to read keyfile " << argv[3] << std::endl;
				return 1;
			}
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			if (!s || static_cast<std::size_t>(s.gcount()) != len) {
				std::cerr << "short read on keyfile " << argv[3] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			if(keys.FromBuffer (buf, len)) {
				auto signatureLen = keys.GetSignatureLen ();
				uint8_t * signature = new uint8_t[signatureLen];
				out << "#date=" << std::time(nullptr);
				out << "#olddest=" << keys.GetPublic ()->ToBase64 ();
				out << "#oldname=" << argv[4];
				keys.Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
				auto sig = i2p::data::ByteStreamToBase64 (signature, signatureLen);
				out << "#oldsig=" << sig;
				OPENSSL_cleanse(signature, signatureLen);
				delete[] signature;
				std::cout << out.str () << std::endl;
			} else {
				std::cout << "Failed to load keyfile " << argv[3] << std::endl;
				return 1;
			}
			OPENSSL_cleanse(buf, len);
			delete[] buf;
		}
	}
	else if (arg == "step3") {
		if (argc != 4) { help(); return -1; }
		std::ifstream t(argv[2]);
		std::ifstream s(argv[3], std::ifstream::binary);
		std::string regtxt;
		std::stringstream out;

		if (t.is_open ()) {
			while (getline (t, regtxt)) out << regtxt;
			t.close();
		} else {
			std::cout << "Failed to read file with STEP2 output" << std::endl;
			exit(1);
		}

		if (s.is_open ()) {
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			if (len == (size_t)-1 || len > 64*1024*1024) {
				std::cerr << "Failed to read keyfile " << argv[3] << std::endl;
				return 1;
			}
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			if(keys.FromBuffer (buf, len)) {
				auto signatureLen = keys.GetSignatureLen ();
				uint8_t * signature = new uint8_t[signatureLen];
				keys.Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
				auto sig = i2p::data::ByteStreamToBase64 (signature, signatureLen);
				out << "#sig=" << sig;
				OPENSSL_cleanse(signature, signatureLen);
				delete[] signature;
				std::cout << out.str () << std::endl;
			} else {
				std::cout << "Failed to load keyfile " << argv[3] << std::endl;
				return 1;
			}
			OPENSSL_cleanse(buf, len);
			delete[] buf;
		}
	}
	else {
		help(); exit(1);
	}

	return 0;
}
