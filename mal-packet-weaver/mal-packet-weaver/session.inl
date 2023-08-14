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
        const auto &packet = static_cast<const Packet &>(packet_arg);
        ByteArray buffer = ByteArray{ uint32_to_bytes(packet.type) };
        packet.serialize(buffer);
        if (encryption_)
        {
            buffer = encryption_->encrypt(buffer);
        }
        // byte to check if connection is secured or not.
        buffer.insert(buffer.begin(), encryption_ ? std::byte{ 1 } : std::byte{ 0 });
        ByteArray *value = new ByteArray{ std::move(buffer) };
        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(1000), 2, 1, 0.1);
        while (alive_)
        {
            if (packets_to_send_.push(value))
            {
                value = nullptr;
                break;
            }
            std::this_thread::sleep_for(backoff.get_current_delay());
            backoff.increase_delay();
        }
        if (!alive_ || value != nullptr)
        {
            delete value;
            return false;
        }
        return true;
    }

    inline void Session::read_bytes_to(ByteArray &byte_array, const size_t amount)
    {
        const size_t current_size = byte_array.size();
        byte_array.resize(current_size + amount);
        buffer_.sgetn(byte_array.as<char>() + current_size * sizeof(char), amount);
    }

}  // namespace mal_packet_weaver