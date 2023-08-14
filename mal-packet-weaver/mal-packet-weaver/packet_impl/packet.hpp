#pragma once
#include "../common.hpp"

namespace mal_packet_weaver
{
    /// Forward declaration of the Packet class.
    class Packet;

    using PacketSubsystemID = uint16_t;  ///< Type alias for packet subsystem IDs.
    using PacketID = uint16_t;           ///< Type alias for packet IDs.

    /// Unique identifier for a packet, combining subsystem and packet IDs.
    using UniquePacketID = uint32_t;

    /// Type alias for packet deserialization function.
    using PacketDeserializeFunc = std::function<std::unique_ptr<Packet>(const ByteView)>;

    /// Convert a PacketSubsystemID to a uint32_t value.
    constexpr uint32_t PacketSubsystemIDToUint32(PacketSubsystemID subsystem_type) noexcept
    {
        return static_cast<uint32_t>(subsystem_type) << 16;
    }

    /// Extract PacketSubsystemID from a UniquePacketID.
    constexpr PacketSubsystemID UniquePacketIDToPacketSubsystemID(UniquePacketID subsystem_type) noexcept
    {
        return static_cast<PacketSubsystemID>((subsystem_type & 0xFFFF0000) >> 16);
    }

    /// Extract PacketID from a UniquePacketID.
    constexpr PacketID UniquePacketIDToPacketID(UniquePacketID subsystem_type) noexcept
    {
        return static_cast<PacketID>(subsystem_type & 0xFFFF);
    }

    /// Create a UniquePacketID from subsystem and packet IDs.
    constexpr UniquePacketID CreatePacketID(PacketSubsystemID subsystem_id, PacketID packet_id) noexcept
    {
        return (static_cast<UniquePacketID>(subsystem_id) << 16) | packet_id;
    }

    /// Base class for all packets.
    class Packet : public non_copyable
    {
    private:
        static Measurer<std::chrono::steady_clock> measurer;  ///< Measurer for packet timestamps.
    public:
        /// Constructor for Packet class.
        explicit Packet(const UniquePacketID type, const float time_to_live)
            : type(type), time_to_live(time_to_live), timestamp_{ measurer.elapsed() }
        {
        }

        Packet(Packet &&) = default;
        Packet &operator=(Packet &&) = default;

        /// @todo: use RBAC system to manage permissions

        /// Virtual destructor for Packet class.
        virtual ~Packet() = default;

        /// Serialize the packet into a ByteArray.
        virtual void serialize(ByteArray &buffer) const = 0;

        /// Get the timestamp when the packet was received.
        [[nodiscard]] float timestamp() const noexcept { return timestamp_; }

        /// Get the time elapsed since the packet was received.
        [[nodiscard]] float get_packet_time_alive() const noexcept { return measurer.elapsed() - timestamp_; }

        /// Check if the packet has expired based on its time-to-live.
        [[nodiscard]] bool expired() const noexcept { return get_packet_time_alive() > time_to_live; }

        const UniquePacketID type;  ///< Unique packet ID.
        const float time_to_live;   ///< Time-to-live for the packet.
        const float timestamp_;     ///< Timestamp when the packet was received.
    };

    /**
     * @brief A templated class representing a derived packet from the base Packet class.
     *
     * Derived packets are specialized implementations of Packet that define specific packet types.
     *
     * They inherit serialization and deserialization functionality from the base Packet class and
     * can be used to encapsulate and manage different types of data for communication.
     *
     * The template parameter `PacketType` specifies the concrete derived packet type.
     *
     * @note We cannot check within this class if requirements for packet type are satisfied, but IsPacket concept is
     *       used thoroughly within the library. It requires that the class should be final, declared time_to_live,
     *       static_type and deserialize functions.
     *
     * @tparam PacketType The specific derived packet type.
     *
     *
     */
    template <typename PacketType>
    class DerivedPacket : public Packet
    {
    public:
        /**
         * @brief Constructor for the DerivedPacket class.
         *
         * Initializes the packet with the static_type and time_to_live of the PacketType.
         */
        DerivedPacket() : Packet(PacketType::static_type, PacketType::time_to_live) {}

        /**
         * @brief Virtual destructor for the DerivedPacket class.
         */
        virtual ~DerivedPacket() = default;

        /**
         * @brief Serialize the derived packet data into a ByteArray.
         *
         * This function uses Boost's binary serialization to convert the packet's contents
         * into a binary representation and appends it to the provided buffer.
         *
         * @param buffer The ByteArray to which the serialized data is appended.
         */
        void serialize(ByteArray &buffer) const override
        {
            std::ostringstream oss;
            boost::archive::binary_oarchive oa(oss);
            oa << static_cast<const PacketType &>(*this);
            std::string const &s = oss.str();
            buffer.append(s);
        }

        /**
         * @brief Deserialize a byte view into a unique pointer of the specified packet type.
         *
         * This static function is responsible for deserializing the binary data from a ByteView
         * and reconstructing a unique pointer to a PacketType instance.
         *
         * @param buffer The ByteView containing the binary serialized data.
         * @return A unique pointer to the deserialized PacketType instance.
         */
        [[nodiscard]] static std::unique_ptr<Packet> deserialize(const ByteView buffer)
        {
            const auto char_view = buffer.as<char>();
            const std::string s(char_view, buffer.size());
            std::istringstream iss(s);
            boost::archive::binary_iarchive ia(iss);
            std::unique_ptr<PacketType> derived_packet = std::make_unique<PacketType>();
            ia >> *derived_packet;
            return derived_packet;
        }
    };

    /// Concept to check if a given type satisfies the requirements of being a packet.
    template <typename T>
    concept IsPacket = requires(T packet)
    {
        std::is_final_v<T>;
        std::is_base_of_v<DerivedPacket<T>, T>;
        std::same_as<std::decay_t<decltype(T::static_type)>, UniquePacketID>;
        std::same_as<std::decay_t<decltype(T::time_to_live)>, float>;
    };

}  // namespace mal_packet_weaver
