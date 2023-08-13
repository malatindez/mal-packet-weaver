#pragma once
#include "../common.hpp"
namespace mal_packet_weaver::crypto
{
    class EncryptionInterface
    {
    public:
        virtual ~EncryptionInterface() = default;
        virtual ByteArray encrypt(const ByteView plaintext) const = 0;
        virtual ByteArray decrypt(const ByteView ciphertext) const = 0;
        virtual void encrypt_in_place(ByteArray &plaintext) const = 0;
        virtual void decrypt_in_place(ByteArray &ciphertext) const = 0;
    };
}  // namespace mal_packet_weaver::crypto