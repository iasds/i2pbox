#include <iostream>
#include <cstring>
#include "Crypto.h"
#include "tools.h"

struct Command {
    const char *name;
    const char *desc;
    int (*func)(int, char**);
};

static const Command commands[] = {
    {"vain",           "Generate vanity .b32.i2p address",                    tool_vain},
    {"keygen",         "Generate random I2P keys",                            tool_keygen},
    {"keyinfo",        "Display info about a private key",                    tool_keyinfo},
    {"famtool",        "Router family: generate, sign, or verify",            tool_famtool},
    {"routerinfo",     "Display router info (hosts, ports, firewall rules)",  tool_routerinfo},
    {"regaddr",        "Register an I2P address",                             tool_regaddr},
    {"regaddr_3ld",    "Register a 3LD address (3-step process)",             tool_regaddr_3ld},
    {"i2pbase64",      "Encode/decode I2P Base64",                            tool_i2pbase64},
    {"offlinekeys",    "Generate offline signing keys",                       tool_offlinekeys},
    {"b33address",     "Convert Base64 destination to b33 address",           tool_b33address},
    {"regaddralias",   "Register an address alias",                           tool_regaddralias},
    {"x25519",         "Generate X25519 key pair for encrypted LeaseSet",     tool_x25519},
    {"verifyhost",     "Verify host record signature",                        tool_verifyhost},
    {"autoconf_i2pd",  "Interactive i2pd.conf generator",                     tool_autoconf_i2pd},
    {nullptr, nullptr, nullptr}
};

static void print_usage(const char *prog) {
    std::cout << "i2pbox — unified I2P toolkit (based on PurpleI2P/i2pd-tools)\n\n"
              << "Usage: " << prog << " <command> [args...]\n\n"
              << "Commands:\n";
    for (const Command *c = commands; c->name; ++c) {
        std::cout << "  " << c->name;
        int pad = 16 - (int)strlen(c->name);
        for (int i = 0; i < pad; ++i) std::cout << ' ';
        std::cout << c->desc << '\n';
    }
    std::cout << "\nExample: " << prog << " keygen my-router.keys EdDSA_SHA512_Ed25519\n";
    std::cout << "         " << prog << " keyinfo privatekey.dat\n";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd(argv[1]);

    // Handle help flags at top level
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        print_usage(argv[0]);
        return 0;
    }

    for (const Command *c = commands; c->name; ++c) {
        if (cmd == c->name) {
            i2p::crypto::InitCrypto(true); // precomputation on (needed by vain)
            // Shift argv: i2pbox cmd args... → cmd args...
            int ret = c->func(argc - 1, argv + 1);
            i2p::crypto::TerminateCrypto();
            return ret;
        }
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage(argv[0]);
    return 1;
}
