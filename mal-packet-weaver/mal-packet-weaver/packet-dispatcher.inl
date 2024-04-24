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
        auto packet_type = DerivedPacket::static_unique_id;
        auto promise = std::make_shared<std::promise<BasePacketPtr>>();
        enqueue_promise(packet_type, promise);
        auto future = promise->get_future();
        co_await boost::asio::this_coro::executor;

        spdlog::debug("Waiting for packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);

        if (timeout <= 0)
        {
            auto base = co_await await_future(future, co_await boost::asio::this_coro::executor);
            Assert(base->type == DerivedPacket::static_unique_id);  // Sanity check
            spdlog::trace("Received packet: {}, ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }

        try
        {
            auto base = co_await await_future(future, co_await boost::asio::this_coro::executor,
                                              std::chrono::microseconds(static_cast<size_t>(timeout * 1e6f)));
            Assert(base->type == DerivedPacket::static_unique_id);  // Sanity check
            spdlog::trace("Received packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }
        catch (std::runtime_error &err)
        {
            spdlog::warn("Timed out waiting for packet {} ({}): {}", DerivedPacket::static_unique_id,
                         DerivedPacket::static_packet_name, err.what());
            co_return nullptr;
        }
        catch (std::exception &exception)
        {
            spdlog::error("An error occurred while waiting for packet {} ({}): {}", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name, exception.what());
            co_return nullptr;
        }
    }

    template <IsPacket DerivedPacket>
    boost::asio::awaitable<std::unique_ptr<DerivedPacket>> PacketDispatcher::await_packet(
        PacketFilterFunc<DerivedPacket> filter, float timeout)
    {
        auto packet_type = DerivedPacket::static_unique_id;
        auto promise = std::make_shared<std::promise<BasePacketPtr>>();
        enqueue_filter_promise(packet_type, { [passedFilter = filter](BasePacketPtr const &packet) {
                                                 return passedFilter(*reinterpret_cast<DerivedPacket *>(packet.get()));
                                             },
                                              promise });
        auto future = promise->get_future();
        co_await boost::asio::this_coro::executor;

        spdlog::trace("Waiting for packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);

        if (timeout <= 0)
        {
            auto base = co_await await_future(future, co_await boost::asio::this_coro::executor);
            Assert(base->type == DerivedPacket::static_unique_id);  // Sanity check
            spdlog::trace("Received packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }

        try
        {
            auto base = co_await await_future(future, co_await boost::asio::this_coro::executor,
                                              std::chrono::microseconds(static_cast<size_t>(timeout * 1e6f)));
            Assert(base->type == DerivedPacket::static_unique_id);  // Sanity check
            spdlog::trace("Received packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
            co_return std::unique_ptr<DerivedPacket>(reinterpret_cast<DerivedPacket *>(base.release()));
        }
        catch (std::runtime_error &err)
        {
            spdlog::warn("Timed out waiting for packet: {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
            co_return nullptr;
        }
        catch (std::exception &exception)
        {
            spdlog::error("An error occurred while waiting for packet {} ({}): {}", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name,
                          exception.what());
            co_return nullptr;
        }
    }

    template <IsPacket DerivedPacket>
    void PacketDispatcher::register_default_handler(PacketHandlerFunc<DerivedPacket> handler,
                                                    PacketFilterFunc<DerivedPacket> filter, float delay)
    {
        spdlog::trace("Posting task to register default handler for packet {} ({})", DerivedPacket::static_unique_id, DerivedPacket::static_packet_name);
        constexpr auto packet_id = DerivedPacket::static_unique_id;
        
        handler_tuple tuple =
                    handler_tuple{ delay,
                                   !bool(filter)
                                       ? PacketFilterFunc<Packet>{}
                                       : ([moved_filter = std::move(filter)](Packet const &packet) -> bool
                                          { return moved_filter(reinterpret_cast<DerivedPacket const &>(packet)); }),
                                   [moved_handler = std::move(handler)](std::unique_ptr<Packet> &&packet)
                                   {
                                       auto ptr = reinterpret_cast<DerivedPacket *>(packet.release());
                                       auto uptr = std::unique_ptr<DerivedPacket>(ptr);
                                       moved_handler(std::move(uptr));
                                   } };
        default_handlers_input_.push(std::pair{packet_id, std::move(tuple)});
        signal_handler_.notify();
    }

    inline void PacketDispatcher::enqueue_promise(UniquePacketID packet_id, shared_packet_promise promise)
    {
        spdlog::trace("Posting task to enqueue promise for packet {}", packet_id);
        promise_map_input_.push(std::pair{ packet_id, std::move(promise) });
        signal_handler_.notify();
    }

    inline void PacketDispatcher::enqueue_filter_promise(UniquePacketID packet_id, promise_filter filtered_promise)
    {
        spdlog::trace("Posting task to enqueue promise with filter for packet {}", packet_id);
        promise_filter_map_input_.push(std::pair{packet_id, std::move(filtered_promise)});
        signal_handler_.notify();
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
                        spdlog::trace("Fulfilled filtered promise for packet_id: {} ({})", packet_id, packet->packet_name());
                        promise_filter.second->set_value(std::move(packet));
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
                spdlog::trace("Fulfilled promise for packet_id: {} ({})", packet_id, packet->packet_name());
                it->second.front()->set_value(std::move(packet));
                it->second.pop_front();
                return true;
            }
        }

        spdlog::trace("No promises to fulfill for packet_id: {} ({})", packet_id, packet->packet_name());
        return false;
    }

    inline bool PacketDispatcher::fulfill_handlers(UniquePacketID packet_id, BasePacketPtr &packet,
                                                   float &min_handler_timestamp, SteadyTimer &timer)
    {
        {
            auto it = default_handlers_.find(packet_id);
            if (it == default_handlers_.end())
            {
                goto fulfill_handlers_exit;
            }

            for (auto &[delay, filter, handler] : it->second)
            {
                if (delay > packet->get_packet_time_alive())
                {
                    min_handler_timestamp = std::min<float>(min_handler_timestamp, timer.elapsed() + delay - packet->get_packet_time_alive());
                    spdlog::trace("Handler delay for packet_id {} ({}) is greater than packet time alive.", packet_id, packet->packet_name());
                    continue;
                }

                if (bool(filter) && !filter(*packet))
                {
                    spdlog::trace("Filter condition not satisfied for packet_id: {} ({})", packet_id, packet->packet_name());
                    continue;
                }

                spdlog::trace("Fulfilled handler for packet_id: {} ({})", packet_id, packet->packet_name());
                handler(std::move(packet));
                return true;
            }

            spdlog::trace("No suitable default handler to fulfill for packet_id: {} ({})", packet_id, packet->packet_name());
        }
        fulfill_handlers_exit:
        {
            auto it = subsystem_handlers_.find(UniquePacketIDToPacketSubsystemID(packet_id));
            if (it == subsystem_handlers_.end())
            {
                spdlog::trace("No handlers to fulfill for packet_id: {} ({})", packet_id, packet->packet_name());
                return false;
            }
            for (auto &[delay, filter, handler] : it->second)
            {
                if (delay > packet->get_packet_time_alive())
                {
                    min_handler_timestamp =
                        std::min<float>(min_handler_timestamp, timer.elapsed() + delay - packet->get_packet_time_alive());
                    spdlog::trace("Handler delay for packet_id {} ({}) is greater than packet time alive.", packet_id, packet->packet_name());
                    continue;
                }

                if (bool(filter) && !filter(*packet))
                {
                    spdlog::trace("Filter condition not satisfied for packet_id: {} ({})", packet_id, packet->packet_name());
                    continue;
                }

                spdlog::trace("Fulfilled handler for packet_id: {} ({})", packet_id, packet->packet_name());
                handler(std::move(packet));
                return true;
            }
        }
        return false;
    }

    inline void PacketDispatcher::push_packet(BasePacketPtr &&packet)
    {
        spdlog::trace("Pushed packet {} to unprocessed_packets_input_ queue.", packet->packet_name());
        unprocessed_packets_input_.push(std::move(packet));
        signal_handler_.notify();
    }

}  // namespace mal_packet_weaver