#pragma once

#include "packet.hpp"

namespace mal_packet_weaver
{
    template <typename T>
    struct PacketTypeRegistrationHelperNoexcept;
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
         * that satisfy the IsPacket concept. The function associates the packet's static_unique_id
         * with its deserialize member function.
         *
         * @tparam PacketType The packet type that satisfies the IsPacket concept.
         */
        template <IsPacket PacketType>
        static inline void RegisterDeserializer()
        {
            if (auto it = instance().packet_deserializers_.find(PacketType::static_unique_id);
                it != instance().packet_deserializers_.end())
            {
                std::unique_ptr<Packet> (*const *ptr)(const ByteView) =
                    it->second.target<std::unique_ptr<Packet> (*)(const ByteView)>();
                if (ptr && ptr == &(&PacketType::deserialize))  // Same target
                {
                    return;
                }
                std::string exception_msg =
                    "An error occured while trying to register packet deserializer: it is already initialized for this unique packet id with different function!";
#if _DEBUG
                auto t = instance().type_names.at(PacketType::static_unique_id);
                auto hex = [](int value) -> std::string
                {
                    std::stringstream stream;
                    stream << std::hex << value;
                    return stream.str();
                };

                exception_msg += "\n        It is already initialized for type with name: " + std::string(t) +
                                 " with an ID of 0x" + hex(PacketType::static_unique_id);
                exception_msg += ".\n        You are passing " + std::string(typeid(PacketType).name()) +
                                 " with an ID of 0x" + hex(PacketType::static_unique_id);
                exception_msg += ".\n        Please check static unique IDs for these packets.";
#endif
                spdlog::critical(exception_msg);
                throw std::invalid_argument(exception_msg.c_str());
            }
            instance().packet_deserializers_[PacketType::static_unique_id] = PacketType::deserialize;

            const char *type_name = typeid(PacketType).name();

            spdlog::info("Registered deserializer for {} with id {}", type_name, PacketType::static_unique_id);
#if _DEBUG
            instance().type_names[PacketType::static_unique_id] = type_name;
#endif
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
        static void RegisterDeserializer(UniquePacketID packet_id, PacketDeserializeFunc factory)
        {
            if (auto it = instance().packet_deserializers_.find(packet_id);
                it != instance().packet_deserializers_.end())
            {
                std::unique_ptr<Packet> (*const *ptr)(const ByteView) =
                    factory.target<std::unique_ptr<Packet> (*)(const ByteView)>();
                if (!ptr || ptr == it->second.target<std::unique_ptr<Packet> (*)(const ByteView)>())
                {
                    throw std::invalid_argument("Packet deserializer already initialized with different function!");
                }
                return;
            }
            instance().packet_deserializers_[packet_id] = factory;
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
        [[nodiscard]] static inline std::unique_ptr<Packet> Deserialize(const ByteView &bytearray,
                                                                        UniquePacketID packet_type)
        {
            auto it = instance().packet_deserializers_.find(packet_type);
            if (it != instance().packet_deserializers_.end())
            {
                return it->second(bytearray);
            }
            // TODO: MAL_PACKET_WEAVER_VERBOSE_LEVEL, output to spdlog if there's no deserializer.
            return nullptr;
        }
        /**
         * @brief Instance of the Packet Factory.
         */
        static PacketFactory &instance()
        {
            if (instance_ == nullptr)
            {
                instance_ = std::unique_ptr<PacketFactory>(new PacketFactory);
            }
            return *instance_;
        }

    private:
        PacketFactory() = default;
        static std::unique_ptr<PacketFactory> instance_;
        /**
         * @brief Map storing registered packet deserializer functions.
         */
        std::unordered_map<UniquePacketID, PacketDeserializeFunc> packet_deserializers_;
#if _DEBUG
        std::unordered_map<UniquePacketID, const char *> type_names;
#endif
    };

    /**
     * @brief Helper class for registering a packet type with the PacketFactory.
     *
     * This class is used to register a specific packet type with the PacketFactory
     * during static initialization. It ensures that the packet type is registered
     * with the PacketFactory before the main function is called.
     *
     * @tparam T The packet type to be registered.
     */
    template <typename T>
    struct PacketTypeRegistrationHelper
    {
        /**
         * @brief Constructor. Registers the packet type with the PacketFactory.
         */
        PacketTypeRegistrationHelper() { PacketFactory::RegisterDeserializer<T>(); }
    };

}  // namespace mal_packet_weaver
