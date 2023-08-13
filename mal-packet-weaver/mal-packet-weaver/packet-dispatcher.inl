#pragma once
#include "packet-dispatcher.hpp"
namespace mal_packet_weaver
{
    inline void PacketDispatcher::enqueue_packet(BasePacketPtr &&packet)
    {
        spdlog::trace("Enqueuing packet for processing.");
        push_packet(std::move(packet));
    }
    template <IsPacket DerivedPacket>
    boost::asio::awaitable<std::unique_ptr<DerivedPacket>> PacketDispatcher::await_packet(float timeout)
    {
        auto packet_type = DerivedPacket::static_type;
        auto promise = std::make_shared<std::promise<BasePacketPtr>>();
        enqueue_promise(packet_type, promise);
        auto future = promise->get_future();
        co_await boost::asio::this_coro::executor;

        spdlog::debug("Waiting for packet: {}", DerivedPacket::static_type);

        if (timeout <= 0)
        {
            auto base = future.get();
            Assert(base->type == DerivedPacket::static_type);  // Sanity check
            spdlog::trace("Received packet: {}", DerivedPacket::static_type);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }

        std::future_status status = future.wait_for(std::chrono::microseconds(size_t(timeout * 1e6f)));

        if (status == std::future_status::ready)
        {
            auto base = future.get();
            Assert(base->type == DerivedPacket::static_type);  // Sanity check
            spdlog::trace("Received packet: {}", DerivedPacket::static_type);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }
        else if (status == std::future_status::timeout)
        {
            spdlog::warn("Timed out waiting for packet: {}", DerivedPacket::static_type);
            co_return nullptr;
        }
        else
        {
            spdlog::error("An error occurred while waiting for packet: {}", DerivedPacket::static_type);
            co_return nullptr;
        }
    }

    template <IsPacket DerivedPacket>
    boost::asio::awaitable<std::unique_ptr<DerivedPacket>> PacketDispatcher::await_packet(
        PacketFilterFunc<DerivedPacket> filter, float timeout)
    {
        auto packet_type = DerivedPacket::static_type;
        auto promise = std::make_shared<std::promise<BasePacketPtr>>();
        enqueue_filter_promise(packet_type, { [passedFilter = filter](BasePacketPtr const &packet) {
                                                 return passedFilter(*reinterpret_cast<DerivedPacket *>(packet.get()));
                                             },
                                              promise });

        auto future = promise->get_future();
        co_await boost::asio::this_coro::executor;

        spdlog::trace("Waiting for packet: {}", DerivedPacket::static_type);

        if (timeout <= 0)
        {
            auto base = future.get();
            Assert(base->type == DerivedPacket::static_type);  // Sanity check
            spdlog::trace("Received packet: {}", DerivedPacket::static_type);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }

        std::future_status status = future.wait_for(std::chrono::microseconds(size_t(timeout * 1e6f)));

        if (status == std::future_status::ready)
        {
            auto base = future.get();
            Assert(base->type == DerivedPacket::static_type);  // Sanity check
            spdlog::trace("Received packet: {}", DerivedPacket::static_type);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }
        else if (status == std::future_status::timeout)
        {
            spdlog::warn("Timed out waiting for packet: {}", DerivedPacket::static_type);
            co_return nullptr;
        }
        else
        {
            spdlog::error("An error occurred while waiting for packet: {}", DerivedPacket::static_type);
            co_return nullptr;
        }
    }

    template <IsPacket DerivedPacket>
    void PacketDispatcher::register_default_handler(PacketHandlerFunc<DerivedPacket> handler,
                                                    PacketFilterFunc<DerivedPacket> filter, float delay)
    {
        spdlog::trace("Posting task to register default handler for packet {}", DerivedPacket::static_type);
        default_handlers_input_strand_.post(
            [this, delay, movedFilter = filter, movedHandler = handler]() __lambda_force_inline -> void
            {
                constexpr auto packet_id = DerivedPacket::static_type;
                spdlog::trace("Registered default handler for packet {}!", packet_id);
                handler_tuple tuple =
                    handler_tuple{ delay,
                                   !bool(movedFilter)
                                       ? PacketFilterFunc<Packet>{}
                                       : ([movedFilter](Packet const &packet) -> bool
                                          { return movedFilter(reinterpret_cast<DerivedPacket const &>(packet)); }),
                                   [movedHandler](std::unique_ptr<Packet> &&packet)
                                   {
                                       auto ptr = reinterpret_cast<DerivedPacket *>(packet.release());
                                       auto uptr = std::unique_ptr<DerivedPacket>(ptr);
                                       movedHandler(std::move(uptr));
                                   } };
                default_handlers_input_.emplace_back(std::pair{ packet_id, tuple });
                default_handlers_input_updated_.test_and_set(std::memory_order_release);
            });
    }

    inline void PacketDispatcher::enqueue_promise(UniquePacketID packet_id, shared_packet_promise promise)
    {
        spdlog::trace("Posting task to enqueue promise for packet {}", packet_id);
        promise_map_input_strand_.post(
            [this, packet_id, moved_promise = std::move(promise)]() mutable
            {
                spdlog::trace("Promise enqueued for packet {}!", packet_id);
                promise_map_input_.emplace_back(std::pair{ packet_id, std::move(moved_promise) });
                promise_map_input_updated_.test_and_set(std::memory_order_release);
            });
    }

    inline void PacketDispatcher::enqueue_filter_promise(UniquePacketID packet_id, promise_filter filtered_promise)
    {
        spdlog::trace("Posting task to enqueue promise with filter for packet {}", packet_id);
        promise_filter_map_input_strand_.post(
            [this, packet_id, moved_filtered_promise = std::move(filtered_promise)]() mutable
            {
                spdlog::trace("Promise with filter enqueued for packet {}!", packet_id);
                promise_filter_map_input_.emplace_back(std::pair{ packet_id, std::move(moved_filtered_promise) });
                promise_filter_map_input_updated_.test_and_set(std::memory_order_release);
            });
    }

    inline bool PacketDispatcher::fulfill_promises(UniquePacketID packet_id, BasePacketPtr &packet)
    {
        // Fulfill first filtered promise in filter_promise_map
        {
            auto it = promise_filter_map_.find(packet_id);
            if (it != promise_filter_map_.end())
            {
                for (auto &promise_filter : it->second)
                {
                    if (!promise_filter.first || promise_filter.first(packet))
                    {
                        promise_filter.second->set_value(std::move(packet));
                        spdlog::trace("Fulfilled filtered promise for packet_id: {}", packet_id);
                        return true;
                    }
                }
            }
        }

        // Fulfill the first promise in promise_map
        {
            auto it = promise_map_.find(packet_id);
            if (it != promise_map_.end() && !it->second.empty())
            {
                it->second.front()->set_value(std::move(packet));
                it->second.pop_front();
                spdlog::trace("Fulfilled promise for packet_id: {}", packet_id);
                return true;
            }
        }

        spdlog::trace("No promises to fulfill for packet_id: {}", packet_id);
        return false;
    }

    inline bool PacketDispatcher::fulfill_handlers(UniquePacketID packet_id, BasePacketPtr &packet,
                                                   float &min_handler_timestamp, SteadyTimer &timer)
    {
        auto it = default_handlers_.find(packet_id);
        if (it == default_handlers_.end())
        {
            spdlog::warn("No handlers to fulfill for packet_id: {}", packet_id);
            return false;
        }

        for (auto &[delay, filter, handler] : it->second)
        {
            if (delay > packet->get_packet_time_alive())
            {
                min_handler_timestamp =
                    std::min<float>(min_handler_timestamp, timer.elapsed() + delay - packet->get_packet_time_alive());
                spdlog::trace("Handler delay for packet_id {} is greater than packet time alive.", packet_id);
                continue;
            }

            if (bool(filter) && !filter(*packet))
            {
                spdlog::trace("Filter condition not satisfied for packet_id: {}", packet_id);
                continue;
            }

            handler(std::move(packet));
            spdlog::trace("Fulfilled handler for packet_id: {}", packet_id);
            return true;
        }

        spdlog::trace("No suitable handlers to fulfill for packet_id: {}", packet_id);
        return false;
    }

    inline void PacketDispatcher::push_packet(BasePacketPtr &&packet)
    {
        unprocessed_packets_input_strand_.post(
            [this, released_packet = packet.release()]()
            {
                BasePacketPtr unique_packet{ released_packet };
                unprocessed_packets_input_.emplace_back(std::move(unique_packet));
                unprocessed_packets_input_updated_.test_and_set(std::memory_order_release);
                spdlog::trace("Pushed packet to unprocessed_packets_input_ queue.");
            });
    }

}  // namespace mal_packet_weaver