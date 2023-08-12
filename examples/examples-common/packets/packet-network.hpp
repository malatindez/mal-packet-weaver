#pragma once
#include "../packet.hpp"
namespace mal_packet_weaver::packet::network
{
    /**
     * @brief Unique packet ID for PingPacket.
     */
    constexpr UniquePacketID PingPacketID = CreatePacketID(PacketSubsystemNetwork, 0x0000);

    /**
     * @brief Unique packet ID for PongPacket.
     */
    constexpr UniquePacketID PongPacketID = CreatePacketID(PacketSubsystemNetwork, 0x0001);

    /**
     * @brief Unique packet ID for MessagePacket.
     */
    constexpr UniquePacketID MessagePacketID = CreatePacketID(PacketSubsystemNetwork, 0x0002);

    /**
     * @brief Unique packet ID for EchoPacket.
     */
    constexpr UniquePacketID EchoPacketID = CreatePacketID(PacketSubsystemNetwork, 0x0003);

    /**
     * @brief Packet for sending a ping signal.
     */
    class PingPacket : public DerivedPacket<class PingPacket>
    {
    public:
        static constexpr UniquePacketID static_type = PingPacketID;
        static constexpr float time_to_live = 10.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class PingPacket>>(*this);
        }
    };

    /**
     * @brief Packet for responding to a ping signal.
     */
    class PongPacket : public DerivedPacket<class PongPacket>
    {
    public:
        static constexpr UniquePacketID static_type = PongPacketID;
        static constexpr float time_to_live = 10.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class PongPacket>>(*this);
        }
    };

    /**
     * @brief Packet for sending a text message.
     */
    class MessagePacket : public DerivedPacket<class MessagePacket>
    {
    public:
        static constexpr UniquePacketID static_type = MessagePacketID;
        static constexpr float time_to_live = 60.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }
        std::string message;

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class MessagePacket>>(*this);
            ar &message;
        }
    };

    /**
     * @brief Packet for echoing a received message.
     */
    class EchoPacket : public DerivedPacket<class EchoPacket>
    {
    public:
        static constexpr UniquePacketID static_type = EchoPacketID;
        static constexpr float time_to_live = 5.0f;
        [[nodiscard]] Permission get_permission() const override { return Permission::ANY; }
        std::string echo_message;

    private:
        friend class boost::serialization::access;
        template <class Archive>
        void serialize(Archive &ar, [[maybe_unused]] const unsigned int version)
        {
            ar &boost::serialization::base_object<DerivedPacket<class EchoPacket>>(*this);
            ar &echo_message;
        }
    };

    /**
     * @brief Register deserializers for network packets.
     */
    inline void RegisterDeserializers()
    {
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<PingPacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<PongPacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<MessagePacket>();
        mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<EchoPacket>();
    }
} // namespace mal_packet_weaver::packet::network