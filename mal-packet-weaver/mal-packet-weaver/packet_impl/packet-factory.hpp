#pragma once

#include "packet.hpp"

namespace mal_packet_weaver::packet
{
    /**
     * @brief A class responsible for registering and creating packet deserializers.
     */
    class PacketFactory
    {
    public:
        /**
         * @brief Register a packet deserializer function for a specific PacketType.
         *
         * This template function allows registration of deserializer functions for packet types
         * that satisfy the IsPacket concept. The function associates the packet's static_type
         * with its deserialize member function.
         *
         * @tparam PacketType The packet type that satisfies the IsPacket concept.
         */
        template <IsPacket PacketType> static inline void RegisterDeserializer()
        {
            if(packet_deserializers_.find(PacketType::static_type) != packet_deserializers_.end())
            {
                throw std::invalid_argument("Packet deserializer already initialized!");
            }
            packet_deserializers_[PacketType::static_type] = PacketType::deserialize;
        }

        /**
         * @brief Register a packet deserializer function for a specific packet ID.
         *
         * This function allows registration of a custom packet deserializer function for a
         * unique packet ID. It associates the given packet_id with the provided factory function.
         *
         * @param packet_id The unique packet ID.
         * @param factory The packet deserialization factory function.
         */
        static inline void RegisterDeserializer(UniquePacketID packet_id,
                                                PacketDeserializeFunc const &factory)
        {
            if(packet_deserializers_.find(packet_id) != packet_deserializers_.end())
            {
                throw std::invalid_argument("Packet deserializer already initialized!");
            }
            packet_deserializers_[packet_id] = factory;
        }

        /**
         * @brief Deserialize a byte view into a unique pointer of the specified packet type.
         *
         * This function uses the registered packet deserializer functions to deserialize the
         * binary data from a ByteView and reconstruct a unique pointer to a packet instance.
         *
         * @param bytearray The ByteView containing the binary serialized data.
         * @param packet_type The unique packet ID specifying the packet type.
         * @return A unique pointer to the deserialized packet instance.
         */
        [[nodiscard]] static inline std::unique_ptr<Packet> Deserialize(const mal_toolkit::ByteView &bytearray,
                                                                        UniquePacketID packet_type)
        {
            auto it = packet_deserializers_.find(packet_type);
            if (it != packet_deserializers_.end())
            {
                return it->second(bytearray);
            }
            // TODO: MAL_PACKET_WEAVER_VERBOSE_LEVEL, output to spdlog if there's no deserializer.
            return nullptr;
        }

    private:
        /**
         * @brief Map storing registered packet deserializer functions.
         */
        static std::unordered_map<UniquePacketID, PacketDeserializeFunc> packet_deserializers_;
    };
} // namespace mal_packet_weaver::packet
