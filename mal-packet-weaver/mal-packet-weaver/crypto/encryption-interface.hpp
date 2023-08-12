#pragma once
#include "mal-toolkit/mal-toolkit.hpp"

namespace mal_packet_weaver::crypto
{
    class EncryptionInterface
    {
    public:
        virtual ~EncryptionInterface();
        virtual mal_toolkit::ByteArray encrypt(const mal_toolkit::ByteView plaintext) const = 0;
        virtual mal_toolkit::ByteArray decrypt(const mal_toolkit::ByteView ciphertext) const = 0;
        virtual void encrypt_in_place(mal_toolkit::ByteArray &plaintext) const = 0;
        virtual void decrypt_in_place(mal_toolkit::ByteArray &ciphertext) const = 0;
    };
}