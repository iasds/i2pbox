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

int tool_regaddralias(int argc, char *argv[])
{
	if (argc < 4)
	{
		std::cout << "Usage: regaddralias oldfilename newfilename address" << std::endl;
		return 1;
	}

	if (!isValidName (argv[3]))
	{
		std::cerr << "Invalid address name " << argv[3] << std::endl;
		return 1;
	}

	i2p::data::PrivateKeys oldkeys, newkeys;
	{
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
			if (!s || static_cast<std::size_t>(s.gcount()) != len)
			{
				std::cerr << "short read on keyfile " << argv[1] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			if(!oldkeys.FromBuffer (buf, len))
			{
				std::cout << "Failed to load keyfile " << argv[1] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			OPENSSL_cleanse(buf, len);
			delete[] buf;
		}
		else
		{
			std::cout << "Can't open keyfile " << argv[1] << std::endl;
			return 1;
		}
	}

	{
		std::ifstream s(argv[2], std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			if (len == (size_t)-1 || len > 64*1024*1024)
			{
				std::cerr << "Failed to read keyfile " << argv[2] << std::endl;
				return 1;
			}
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			if (!s || static_cast<std::size_t>(s.gcount()) != len)
			{
				std::cerr << "short read on keyfile " << argv[2] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			if(!newkeys.FromBuffer (buf, len))
			{
				std::cout << "Failed to load keyfile " << argv[2] << std::endl;
				OPENSSL_cleanse(buf, len);
				delete[] buf;
				return 1;
			}
			OPENSSL_cleanse(buf, len);
			delete[] buf;
		}
		else
		{
			std::cout << "Can't open keyfile " << argv[2] << std::endl;
			return 1;
		}
	}

	std::stringstream out;
	out << argv[3] << "="; // address
	out << newkeys.GetPublic ()->ToBase64 ();
	out << "#!action=adddest#olddest=";
	out << oldkeys.GetPublic ()->ToBase64 ();

	auto oldSignatureLen = oldkeys.GetSignatureLen ();
	uint8_t * oldSignature = new uint8_t[oldSignatureLen];
	//char * oldSig = new char[oldSignatureLen*2];
	oldkeys.Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), oldSignature);
	auto oldSig = i2p::data::ByteStreamToBase64 (oldSignature, oldSignatureLen);//, oldSig, oldSignatureLen*2);
	//oldSig[len] = 0;
	out << "#oldsig=" << oldSig;
		OPENSSL_cleanse(oldSignature, oldSignatureLen);
		delete[] oldSignature;
	//delete[] oldSig;

	auto signatureLen = newkeys.GetSignatureLen ();
	uint8_t * signature = new uint8_t[signatureLen];
	//char * sig = new char[signatureLen*2];
	newkeys.Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
	auto sig = i2p::data::ByteStreamToBase64 (signature, signatureLen);//, sig, signatureLen*2);
	//sig[len] = 0;
	out << "#sig=" << sig;
		OPENSSL_cleanse(signature, signatureLen);
		delete[] signature;
	//delete[] sig;

	std::cout << out.str () << std::endl;

	return 0;
}
