#include <iostream>
#include <stdlib.h>
#include "Crypto.h"
#include "Identity.h"
#include "common/key.hpp"
#include "common/secure_file.hpp"

int tool_keygen(int argc, char *argv[])
{
	if (argc < 2)
	{
		std::cout << "Usage: keygen filename <signature type>" << std::endl;
		return -1;
	}
	i2p::data::SigningKeyType type = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
	if (argc > 2) {
		std::string str(argv[2]);
		type = NameToSigType(str);
		if (SigTypeToName(type).find("unknown") != std::string::npos) { std::cerr << "Incorrect signature type" << std::endl; return -2; }
	}
	// RSA signature types are not supported, fallback to EdDSA
	if (type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA256_2048 ||
	    type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA384_3072 ||
	    type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA512_4096) {
		std::cerr << "Warning: RSA signature type is not supported. Using EdDSA instead." << std::endl;
		type = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
	}
	auto keys = i2p::data::PrivateKeys::CreateRandomKeys (type);
	{
		size_t len = keys.GetFullLen ();
		uint8_t * buf = new uint8_t[len];
		len = keys.ToBuffer (buf, len);
		const bool written = i2pbox::WritePrivateFile(argv[1], buf, len);
		OPENSSL_cleanse(buf, len);
		delete[] buf;
		if (!written) {
			std::cerr << "Can't create file " << argv[1] << std::endl;
			return 1;
		}
		std::cout << "Destination " << keys.GetPublic ()->GetIdentHash ().ToBase32 () << " created" << std::endl;
		std::cout << "Signature type: " << SigTypeToName(type) << " (" << type << ")" << std::endl;
	}

	return 0;
}

