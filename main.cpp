#include <iostream>
#include <cstring>
#include <string>
#include "Crypto.h"
#include "tools.h"

struct Command {
    const char *name;
    const char *desc;
    int (*func)(int, char**);
    bool precompute;
};

static const Command commands[] = {
    {"vain",           "Generate vanity .b32.i2p address",                    tool_vain,          true},
    {"keygen",         "Generate random I2P keys",                            tool_keygen,        false},
    {"keyinfo",        "Display info about a private key",                    tool_keyinfo,       false},
    {"famtool",        "Router family: generate, sign, or verify",            tool_famtool,       false},
    {"routerinfo",     "Display router info (hosts, ports, firewall rules)",  tool_routerinfo,    false},
    {"regaddr",        "Register an I2P address",                             tool_regaddr,       false},
    {"regaddr_3ld",    "Register a 3LD address (3-step process)",             tool_regaddr_3ld,   false},
    {"i2pbase64",      "Encode/decode I2P Base64",                            tool_i2pbase64,     false},
    {"offlinekeys",    "Generate offline signing keys",                       tool_offlinekeys,   false},
    {"b33address",     "Convert Base64 destination to b33 address",           tool_b33address,    false},
    {"regaddralias",   "Register an address alias",                           tool_regaddralias,  false},
    {"x25519",         "Generate X25519 key pair for encrypted LeaseSet",     tool_x25519,        false},
    {"verifyhost",     "Verify host record signature",                        tool_verifyhost,    false},
    {"autoconf_i2pd",  "Interactive i2pd.conf generator",                     tool_autoconf_i2pd, false},
    {nullptr, nullptr, nullptr, false}
};

static void print_usage(std::ostream &out) {
    out << "i2pbox — unified I2P toolkit (based on PurpleI2P/i2pd-tools)\n\n"
        << "Usage: i2pbox <command> [args...]\n\n"
        << "Commands:\n";
    for (const Command *c = commands; c->name; ++c) {
        out << "  " << c->name;
        int pad = 16 - (int)strlen(c->name);
        for (int i = 0; i < pad; ++i) out << ' ';
        out << c->desc << '\n';
    }
    out << "\nExample: i2pbox keygen my-router.keys ED25519-SHA512\n";
    out << "         i2pbox keyinfo privatekey.dat\n";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(std::cout);
        return 1;
    }

    std::string cmd(argv[1]);

    // Handle help flags at top level
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        print_usage(std::cout);
        return 0;
    }

    if (cmd == "--version" || cmd == "version" || cmd == "-v" || cmd == "-V") {
        std::cout << "i2pbox " << I2PBOX_VERSION << " (i2pd " << I2PD_VERSION << ")\n";
        return 0;
    }

    for (const Command *c = commands; c->name; ++c) {
        if (cmd == c->name) {
            i2p::crypto::InitCrypto(c->precompute); // precomputed tables only needed by vain
            // Shift argv: i2pbox cmd args... → cmd args...
            int ret = c->func(argc - 1, argv + 1);
            i2p::crypto::TerminateCrypto();
            return ret;
        }
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage(std::cerr);
    return 1;
}
