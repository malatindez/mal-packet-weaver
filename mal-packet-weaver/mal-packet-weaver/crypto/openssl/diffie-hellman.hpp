#pragma once

#ifdef MAL_PACKET_WEAVER_HAS_OPENSSL
namespace mal_packet_weaver::crypto
{
    /**
     * @class DiffieHellmanHelper
     * @brief Provides utility functions for Diffie-Hellman key exchange.
     */
    class DiffieHellmanHelper : non_copyable_non_movable
    {
    public:
        /**
         * @brief Constructs a DiffieHellmanHelper object and generates DH parameters and keys.
         */
        DiffieHellmanHelper()
        {
            EVP_PKEY_WRAPPER params;
            {
                EVP_PKEY_CTX_WRAPPER pkey_ctx_{ EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL) };
                AlwaysAssert(pkey_ctx_ != nullptr, "Error generating DH parameters");
                AlwaysAssert(EVP_PKEY_paramgen_init(pkey_ctx_.get()) == 1, "Error generating DH parameters.");
                AlwaysAssert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx_.get(), NID_X9_62_prime256v1) == 1,
                             "Error generating DH parameters.");
                EVP_PKEY *params_val = nullptr;
                AlwaysAssert(EVP_PKEY_paramgen(pkey_ctx_.get(), &params_val) == 1, "Error generating DH parameters.");
                params.reset(params_val);
            }

            EVP_PKEY_CTX_WRAPPER keygen_ctx_ = nullptr;
            keygen_ctx_.reset(EVP_PKEY_CTX_new(params.get(), NULL));

            AlwaysAssert(keygen_ctx_ != nullptr, "Error initializing PKEY context.");
            AlwaysAssert(EVP_PKEY_keygen_init(keygen_ctx_.get()) == 1, "Error generating DH key");
            EVP_PKEY *pubkey = nullptr;
            AlwaysAssert(EVP_PKEY_keygen(keygen_ctx_.get(), &pubkey) == 1, "Error generating DH key");
            pubkey_.reset(pubkey);
        }

        /**
         * @brief Retrieves the public key as a byte array.
         * @return A ByteArray containing the public key.
         */
        ByteArray get_public_key() const
        {
            BIO_WRAPPER bio{ BIO_new(BIO_s_mem()) };
            AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
            AlwaysAssert(PEM_write_bio_PUBKEY(bio.get(), pubkey_.get()) > 0, "PEM_write_bio_PrivateKey() failed");
            unsigned char *key_data;
            unsigned long key_size = BIO_get_mem_data(bio.get(), &key_data);

            ByteArray public_key;
            public_key.resize(key_size);
            std::copy_n(key_data, key_size, public_key.as<unsigned char>());
            return public_key;
        }

        /**
         * @brief Computes the shared secret key using the peer's public key.
         * @param peer_key_bytes The byte representation of the peer's public key.
         * @return A ByteArray containing the computed shared secret.
         */
        ByteArray get_shared_secret(const ByteView peer_key_bytes) const
        {
            EVP_PKEY_WRAPPER peer_key;
            {
                BIO_WRAPPER bio{ BIO_new_mem_buf(peer_key_bytes.data(), static_cast<int>(peer_key_bytes.size())) };
                AlwaysAssert(bio != nullptr, "BIO_new_file() failed");
                peer_key.reset(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
                AlwaysAssert(peer_key != nullptr, "PEM_read_bio_PUBKEY() failed");
            }

            EVP_PKEY_CTX_WRAPPER ctx{ EVP_PKEY_CTX_new(pubkey_.get(), NULL) };
            AlwaysAssert(ctx != nullptr, "Error initializing PKEY context.");
            AlwaysAssert(EVP_PKEY_derive_init(ctx.get()) == 1, "Error initializing PKEY context.");
            AlwaysAssert(EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) == 1, "Error initializing PKEY context.");

            size_t len;
            AlwaysAssert(EVP_PKEY_derive(ctx.get(), NULL, &len) == 1, "Error initializing PKEY context.");
            ByteArray shared_secret;
            shared_secret.resize(len);
            AlwaysAssert(EVP_PKEY_derive(ctx.get(), shared_secret.as<unsigned char>(), &len) == 1,
                         "Error initializing PKEY context.");
            shared_secret.resize(len);

            return shared_secret;
        }

    private:
        EVP_PKEY_WRAPPER pubkey_; /**< The generated public key. */
    };
}  // namespace mal_packet_weaver::crypto
#endif