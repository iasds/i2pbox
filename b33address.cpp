#include <iostream>
#include <string>
#include <memory>
#include <unistd.h>
#include "Base.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "common/key.hpp"

int tool_b33address(int argc, char *argv[])
{
	// Read a single I2P base64 destination from stdin; print b33 address.
	// The prompt goes to stderr so pipes (keyinfo -d | b33address) stay clean.
	if (isatty(STDIN_FILENO))
		std::cerr << "Waiting for base64 from stdin..." << std::endl;
	std::string base64;
	std::getline (std::cin, base64);
	if (!base64.empty () && base64.back () == '\r')
		base64.pop_back ();
	// Real destinations are <1 KiB of base64; cap to reject pathological fuzz/pipe input early.
	if (base64.size () > 8192) {
		std::cerr << "Invalid base64 address" << std::endl;
		return 1;
	}
	auto ident = std::make_shared<i2p::data::IdentityEx> ();
	std::vector<uint8_t> buf (base64.length ()); // binary data can't exceed base64
	if (ident->FromBase64 (base64) == 0 ||
		i2p::data::Base64ToByteStream (base64, buf.data (), buf.size ()) != ident->GetFullLen ())
	{
		std::cerr << "Invalid base64 address" << std::endl;
		return 1;
	}
	if (ident->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 ||
		ident->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519)
	{
		i2p::data::BlindedPublicKey blindedKey (ident);
		std::cout << "b33 address: " << blindedKey.ToB33 () << ".b32.i2p" << std::endl;
		std::cout << "Today's store hash: " << blindedKey.GetStoreHash ().ToBase64 () << std::endl;
	}
	else
	{
		std::cerr << "Invalid signature type " << SigTypeToName (ident->GetSigningKeyType ()) << std::endl;
		return 1;
	}

	return 0;
}
