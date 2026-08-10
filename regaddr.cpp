#include <iostream>
#include <fstream>
#include <sstream>
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

int tool_regaddr(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cout << "Usage: regaddr filename address" << std::endl;
		return 1;
	}

	if (!isValidName (argv[2]))
	{
		std::cerr << "Invalid address name " << argv[2] << std::endl;
		return 1;
	}

	i2p::data::PrivateKeys keys;
	std::ifstream s(argv[1], std::ifstream::binary);

	if (s.is_open ())
	{
		s.seekg (0, std::ios::end);
		size_t len = s.tellg();
		if (len == (size_t)-1 || len > 64*1024*1024)
		{
			std::cerr << "Failed to read keyfile " << argv[1] << std::endl;
			return 1;
		}
		s.seekg (0, std::ios::beg);
		uint8_t * buf = new uint8_t[len];
		s.read ((char *)buf, len);

		if(keys.FromBuffer (buf, len))
		{
			auto signatureLen = keys.GetSignatureLen ();
			uint8_t * signature = new uint8_t[signatureLen];
			//char * sig = new char[signatureLen*2];
			std::stringstream out;
			out << argv[2] << "="; // address
			out << keys.GetPublic ()->ToBase64 ();
			keys.Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
			auto sig = i2p::data::ByteStreamToBase64 (signature, signatureLen);//, sig, signatureLen*2);
			//sig[len] = 0;
			out << "#!sig=" << sig;
			OPENSSL_cleanse(signature, signatureLen);
			delete[] signature;
			//delete[] sig;
			std::cout << out.str () << std::endl;
		}
		else
		{
			std::cout << "Failed to load keyfile " << argv[1] << std::endl;
			OPENSSL_cleanse(buf, len);
			delete[] buf;
			return 1;
		}

		OPENSSL_cleanse(buf, len);
		delete[] buf;
	} else {
		std::cerr << "Can't open keyfile " << argv[1] << std::endl;
		return 1;
	}

	return 0;
}
