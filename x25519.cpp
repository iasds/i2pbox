#include <openssl/evp.h> 
#include <openssl/bn.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <iomanip>
#include "Base.h"

#define KEYSIZE 32

struct BoxKeys
{
    uint8_t PublicKey[KEYSIZE];
    uint8_t PrivateKey[KEYSIZE];
};

BoxKeys getKeyPair()
{
	BoxKeys keys;
	size_t len = KEYSIZE;

	EVP_PKEY_CTX * Ctx = EVP_PKEY_CTX_new_id (NID_X25519, NULL);
	if (!Ctx)
	{
		std::cerr << "EVP_PKEY_CTX_new_id failed" << std::endl;
		exit (1);
	}
	EVP_PKEY * Pkey = nullptr;
	if (EVP_PKEY_keygen_init (Ctx) != 1 ||
		EVP_PKEY_keygen (Ctx, &Pkey) != 1)
	{
		std::cerr << "EVP_PKEY_keygen failed" << std::endl;
		exit (1);
	}
	if (EVP_PKEY_get_raw_public_key (Pkey, keys.PublicKey, &len) != 1)
	{
		std::cerr << "EVP_PKEY_get_raw_public_key failed" << std::endl;
		exit (1);
	}
	len = KEYSIZE;
	if (EVP_PKEY_get_raw_private_key (Pkey, keys.PrivateKey, &len) != 1)
	{
		std::cerr << "EVP_PKEY_get_raw_private_key failed" << std::endl;
		exit (1);
	}

	EVP_PKEY_CTX_free(Ctx);
	EVP_PKEY_free(Pkey);

	return keys;
}

int tool_x25519(int argc, char *argv[])
{
    if (argc > 1)
    {
        std::string arg (argv[1]);
        if (arg == "--usage" || arg == "--help" || arg == "-h")
        {
            std::cout << "The x25519 keys are used for authentication with an encrypted LeaseSet.\n"
            << "Server side:\n"
            << "  signaturetype = 11\n"
            << "  i2cp.leaseSetType = 5\n"
            << "  i2cp.leaseSetAuthType = 1\n"
            << "  i2cp.leaseSetClient.dh.210 = clientName:PublicKey\n"
            << "Client side:\n"
            << "  i2cp.leaseSetPrivKey = PrivateKey\n\n"
            << "https://i2pd.readthedocs.io/en/latest/user-guide/tunnels/" << std::endl;

            return 0;
        }
        else
        {
            std::cerr << "Unknown argument '" << arg << "'" << std::endl;
            std::cerr << "usage: " << argv[0] << " [--usage|--help|-h]" << std::endl;
            return 1;
        }
    }

    BoxKeys newKeys = getKeyPair();

    //const size_t len_out = 50;
    //char b64Public[len_out] = {0};
    //char b64Private[len_out] = {0};

    auto b64Public = i2p::data::ByteStreamToBase64 (newKeys.PublicKey, KEYSIZE);

    std::cout << "PublicKey: ";
    for (int i = 0; b64Public[i] != 0; ++i)
        std::cout << b64Public[i];

    auto b64Private = i2p::data::ByteStreamToBase64 (newKeys.PrivateKey, KEYSIZE);

    std::cout << "\nPrivateKey: ";
    for (int i = 0; b64Private[i] != 0; ++i)
        std::cout << b64Private[i];
    std::cout << std::endl;

    return 0;
}
