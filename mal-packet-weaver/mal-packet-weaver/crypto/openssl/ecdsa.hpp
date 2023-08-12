#pragma once
#include "sha.hpp"

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
namespace mal_packet_weaver::crypto::ECDSA
{
    /**
     * @brief Returns the OpenSSL curve ID based on the given curve name.
     * @param curve The name of the elliptic curve (e.g., "secp256k1").
     * @return The corresponding OpenSSL curve ID.
     * @throws std::invalid_argument If the curve name is unknown.
     */
    int GetCurveByName(const std::string_view curve)
    {
        if (curve == "secp256k1")
        {
            return NID_secp256k1;
        }
        else if (curve == "secp384r1")
        {
            return NID_secp384r1;
        }
        else if (curve == "secp521r1")
        {
            return NID_secp521r1;
        }
        mal_toolkit::AlwaysAssert(false, "Unknown curve type");
        throw std::invalid_argument("Unknown curve type");
    }

    /**
     * @class KeyPairGenerator
     * @brief Generates ECDSA key pairs for a given curve.
     */
    class KeyPairGenerator : mal_toolkit::non_copyable_non_movable
    {
    public:
        /**
         * @brief Constructs a KeyPairGenerator object for the specified curve.
         * @param curve_id The OpenSSL curve ID.
         */
        explicit KeyPairGenerator(const int curve_id)
        {
            ctx_.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
            mal_toolkit::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new_id() failed");
            mal_toolkit::AlwaysAssert(EVP_PKEY_keygen_init(ctx_.get()) > 0,
                                "EVP_PKEY_keygen_init() failed");
            mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_.get(), curve_id) > 0,
                                "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed");
        }

        /**
         * @brief Constructs a KeyPairGenerator object for the specified curve name.
         * @param curve_name The name of the elliptic curve (e.g., "secp256k1").
         */
        explicit KeyPairGenerator(const std::string_view curve_name)
            : KeyPairGenerator(GetCurveByName(curve_name))
        {
        }

        /**
         * @brief Generates an ECDSA key pair.
         * @return The generated key pair.
         */
        [[nodiscard]] KeyPair generate() const
        {
            EVP_PKEY_WRAPPER pkey;
            {
                EVP_PKEY *pkey_ = nullptr;
                mal_toolkit::AlwaysAssert(EVP_PKEY_keygen(ctx_.get(), &pkey_) > 0,
                                    "EVP_PKEY_keygen() failed");
                pkey.reset(pkey_);
            }
            unsigned char *key_data;
            unsigned long key_size;

            BIO_WRAPPER bio{ BIO_new(BIO_s_mem()) };
            mal_toolkit::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            mal_toolkit::AlwaysAssert(PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0,
                                                         nullptr, nullptr) > 0,
                                "PEM_write_bio_PrivateKey() failed");
            key_size = BIO_get_mem_data(bio.get(), &key_data);

            Key private_key;
            private_key.resize(key_size);
            std::copy_n(key_data, key_size, private_key.as<unsigned char>());

            bio.reset(BIO_new(BIO_s_mem()));
            mal_toolkit::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            mal_toolkit::AlwaysAssert(PEM_write_bio_PUBKEY(bio.get(), pkey.get()) > 0,
                                "PEM_write_bio_PUBKEY() failed");
            key_size = BIO_get_mem_data(bio.get(), &key_data);
            Key public_key;
            public_key.resize(key_size);
            std::copy_n(key_data, key_size, public_key.as<unsigned char>());

            return KeyPair{ private_key, public_key };
        }

    private:
        EVP_PKEY_CTX_WRAPPER ctx_ = nullptr;
    };

    /**
     * @brief The Signer class is responsible for creating digital signatures using private keys.
     */
    class Signer : mal_toolkit::non_copyable_non_movable
    {
    public:
        /**
         * @brief Constructs a Signer object with the specified private key and hash type.
         * @param private_key The private key used for signing.
         * @param hash_type The hash algorithm used for signing.
         */
        Signer(const KeyView private_key, const Hash::HashType hash_type) : hash_type_(hash_type)
        {
            BIO_WRAPPER bio{ BIO_new_mem_buf(private_key.data(),
                                             static_cast<int>(private_key.size())) };
            mal_toolkit::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            pkey_.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
            mal_toolkit::AlwaysAssert(pkey_ != nullptr, "PEM_read_bio_PrivateKey() failed");

            ctx_.reset(EVP_PKEY_CTX_new(pkey_.get(), nullptr));
            mal_toolkit::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new() failed");
            mal_toolkit::AlwaysAssert(EVP_PKEY_sign_init(ctx_.get()) > 0, "EVP_PKEY_sign_init() failed");
            if (hash_type == Hash::HashType::SHA256)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha256()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA384)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha384()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA512)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha512()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else
            {
                mal_toolkit::AlwaysAssert(false, "Unsupported hash type");
            }
        }

        /**
         * @brief Signs a hash using the private key.
         * @param hash The hash to be signed.
         * @return The signature as a mal_toolkit::ByteArray.
         */
        [[nodiscard]] mal_toolkit::ByteArray sign_hash(const Hash hash) const
        {
            mal_toolkit::Assert(hash.hash_type == hash_type_, "Unsupported hash type");

            size_t signature_size = 0;
            mal_toolkit::ByteArray signature;

            mal_toolkit::AlwaysAssert(EVP_PKEY_sign(ctx_.get(), nullptr, &signature_size, hash.as_uint8(),
                                              hash.size()) > 0,
                                "EVP_PKEY_sign() failed");
            signature.resize(signature_size);

            mal_toolkit::AlwaysAssert(EVP_PKEY_sign(ctx_.get(), signature.as<unsigned char>(),
                                              &signature_size, hash.as_uint8(), hash.size()) > 0,
                                "EVP_PKEY_sign() failed");
            signature.resize(signature_size);
            return signature;
        }

        /**
         * @brief Signs binary data using the private key.
         * @param data The binary data to be signed.
         * @return The signature as a mal_toolkit::ByteArray.
         */
        [[nodiscard]] mal_toolkit::ByteArray sign_data(const mal_toolkit::ByteView data) const
        {
            const Hash hash = SHA::ComputeHash(data, hash_type_);
            return sign_hash(hash);
        }

    private:
        EVP_PKEY_CTX_WRAPPER ctx_ = nullptr;
        EVP_PKEY_WRAPPER pkey_ = nullptr;
        const Hash::HashType hash_type_;
    };

    /**
     * @brief The Verifier class is responsible for verifying digital signatures using public keys.
     */
    class Verifier : mal_toolkit::non_copyable_non_movable
    {
    public:
        /**
         * @brief Constructs a Verifier object with the specified public key and hash type.
         * @param public_key The public key used for verification.
         * @param hash_type The hash algorithm used for verification.
         */
        Verifier(const KeyView public_key, const Hash::HashType hash_type) : hash_type_(hash_type)
        {
            BIO_WRAPPER bio{ BIO_new_mem_buf(public_key.data(),
                                             static_cast<int>(public_key.size())) };
            mal_toolkit::AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            pkey_.reset(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
            mal_toolkit::AlwaysAssert(pkey_ != nullptr, "PEM_read_bio_PUBKEY() failed");

            ctx_.reset(EVP_PKEY_CTX_new(pkey_.get(), nullptr));
            mal_toolkit::AlwaysAssert(ctx_ != nullptr, "EVP_PKEY_CTX_new() failed");
            mal_toolkit::AlwaysAssert(EVP_PKEY_verify_init(ctx_.get()) > 0,
                                "EVP_PKEY_verify_init() failed");
            if (hash_type == Hash::HashType::SHA256)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha256()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA384)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha384()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else if (hash_type == Hash::HashType::SHA512)
            {
                mal_toolkit::AlwaysAssert(EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_sha512()) > 0,
                                    "EVP_PKEY_CTX_set_signature_md() failed");
            }
            else
            {
                mal_toolkit::AlwaysAssert(false, "Unsupported hash type");
            }
        }

        /**
         * @brief Verifies a hash's signature.
         * @param hash The hash to be verified.
         * @param signature The signature to be verified.
         * @return `true` if the signature is valid, `false` otherwise.
         */
        [[nodiscard]] bool verify_hash(const Hash hash, const mal_toolkit::ByteView signature) const
        {
            mal_toolkit::Assert(hash.hash_type == hash_type_, "Unsupported hash type");

            return EVP_PKEY_verify(ctx_.get(), signature.as<unsigned char>(), signature.size(),
                                   hash.as_uint8(), hash.size()) > 0;
        }

        /**
         * @brief Verifies the signature of binary data.
         * @param data The binary data to be verified.
         * @param signature The signature to be verified.
         * @return `true` if the signature is valid, `false` otherwise.
         */
        [[nodiscard]] bool verify_data(const mal_toolkit::ByteView data, const mal_toolkit::ByteView signature) const
        {
            const Hash hash = SHA::ComputeHash(data, hash_type_);
            return verify_hash(hash, signature);
        }

    private:
        EVP_PKEY_CTX_WRAPPER ctx_ = nullptr;
        EVP_PKEY_WRAPPER pkey_ = nullptr;
        const Hash::HashType hash_type_;
    };
    /**
     * @deprecated This function is deprecated. Use KeyPairGenerator class instead.
     * @see KeyPairGenerator
     */
    [[deprecated]] [[nodiscard]] KeyPair generate_key_pair(std::string curve_name)
    {
        KeyPairGenerator instance(curve_name);
        return instance.generate();
    }

    /**
     * @deprecated This function is deprecated. Use Signer class instead.
     * @see Signer
     */
    [[deprecated]] [[nodiscard]] mal_toolkit::ByteArray sign_data(const KeyView private_key, const mal_toolkit::ByteView data,
                                                     const Hash::HashType hash_type)
    {
        Signer instance(private_key, hash_type);
        return instance.sign_data(data);
    }

    /**
     * @deprecated This function is deprecated. Use Signer class instead.
     * @see Signer
     */
    [[deprecated]] [[nodiscard]] mal_toolkit::ByteArray sign_hash(const KeyView private_key, const Hash hash)
    {
        Signer instance(private_key, hash.hash_type);
        return instance.sign_hash(hash);
    }

    /**
     * @deprecated This function is deprecated. Use Verifier class instead.
     * @see Verifier
     */
    [[deprecated]] [[nodiscard]] bool verify_data(const KeyView public_key, const mal_toolkit::ByteView data,
                                                  const mal_toolkit::ByteView signature,
                                                  const Hash::HashType hash_type)
    {
        Verifier instance(public_key, hash_type);
        return instance.verify_data(data, signature);
    }

    /**
     * @deprecated This function is deprecated. Use Verifier class instead.
     * @see Verifier
     */
    [[deprecated]] [[nodiscard]] bool verify_hash(const KeyView public_key, const Hash hash,
                                                  const mal_toolkit::ByteView signature)
    {
        Verifier instance(public_key, hash.hash_type);
        return instance.verify_hash(hash, signature);
    }
} // namespace mal_packet_weaver::crypto::ECDSA
#endif