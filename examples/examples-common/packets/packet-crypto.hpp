#pragma once
#include "../packet.hpp"
#include "../crypto/common.hpp"
#include "../crypto/sha.hpp"
#include <boost/endian/conversion.hpp>

namespace mal_packet_weaver::packet::crypto
{
    /**
     * @brief Unique packet ID for DHKeyExchangeRequestPacket.
     */
    constexpr UniquePacketID DHKeyExchangeRequestPacketID =
        CreatePacketID(PacketSubsystemCrypto, 0x0000);

    /**
     * @brief Unique packet ID for DHKeyExchangeResponsePacket.
     */
    constexpr UniquePacketID DHKeyExchangeResponsePacketID =
        CreatePacketID(PacketSubsystemCrypto, 0x0001);

    /**
     * @brief Packet for Diffie-Hellman key exchange request.
     */
    class DHKeyExchangeRequestPacket : public DerivedPacket<class DHKeyExchangeRequestPacket>
    {
    public:
        static constexpr UniquePacketID static_type = DHKeyExchangeRequestPacketID;
        static constexpr float time_to_live = 120.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        ByteArray public_key;

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class DHKeyExchangeRequestPacket>>(
                *this);
            ar &public_key;
        }
    };

    /**
     * @brief Packet for Diffie-Hellman key exchange response.
     */
    class DHKeyExchangeResponsePacket : public DerivedPacket<class DHKeyExchangeResponsePacket>
    {
    public:
        static constexpr UniquePacketID static_type = DHKeyExchangeResponsePacketID;
        static constexpr float time_to_live = 120.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

        /**
         * @brief Calculate the hash of the packet's contents.
         *
         * @return The calculated hash of the packet's contents.
         */
        [[nodiscard]] mal_packet_weaver::crypto::Hash get_hash() const
        {
            ByteArray arr;
            arr.append(public_key, salt,
                       ByteArray::from_integral(boost::endian::little_to_native(static_type)));
            return mal_packet_weaver::crypto::SHA::ComputeHash(
                arr, mal_packet_weaver::crypto::Hash::HashType::SHA256);
        }

        ByteArray public_key;
        ByteArray salt;
        int n_rounds;

        // Signature of the public key, salt and n_rounds.
        ByteArray signature;

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class DHKeyExchangeResponsePacket>>(
                *this);
            ar &public_key;
            ar &signature;
            ar &salt;
            ar &n_rounds;
        }
    };

    /**
     * @brief Register deserializers for DHKeyExchangeRequestPacket and DHKeyExchangeResponsePacket.
     */
    inline void RegisterDeserializers()
    {
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<DHKeyExchangeRequestPacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<DHKeyExchangeResponsePacket>();
    }

} // namespace mal_packet_weaver::packet::crypto