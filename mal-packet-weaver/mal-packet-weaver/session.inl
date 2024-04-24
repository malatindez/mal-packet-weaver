#pragma once
#include "session.hpp"

namespace mal_packet_weaver
{

    template <IsPacket T>
    bool Session::send_packet(const T &packet_arg) requires std::is_base_of_v<Packet, T>
    {
        if (!alive_)
        {
            spdlog::warn("Session is closed, cannot send packet");
            return false;
        }
        spdlog::trace("Encrypting packet {}", packet_arg.packet_name());
        const auto &packet = static_cast<const Packet &>(packet_arg);
        ByteArray buffer = ByteArray{ uint32_to_bytes(packet.type) };
        packet.serialize_to_bytearray(buffer);
        if (encryption_)
        {
            buffer = encryption_->encrypt(buffer);
        }
        // byte to check if connection is secured or not.
        buffer.insert(buffer.begin(), encryption_ ? std::byte{ 1 } : std::byte{ 0 });
        ByteArray *value = new ByteArray{ std::move(buffer) };
        spdlog::trace("Encrypted packet {}", packet_arg.packet_name());
        while (alive_)
        {
            if (packets_to_send_.push(value))
            {
                spdlog::trace("Pushing packet {}", packet_arg.packet_name());
                value = nullptr;
                break;
            }
            std::this_thread::yield();
        }
        if (!alive_ || value != nullptr)
        {
            delete value;
            return false;
        }
        return true;
    }

}  // namespace mal_packet_weaver