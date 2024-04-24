#include "packet-dispatcher.hpp"

#include <SDKDDKVer.h>

#include "common.hpp"

namespace mal_packet_weaver
{
    PacketDispatcher::PacketDispatcher(boost::asio::io_context &io_context)
        : io_context_{ io_context }, signal_handler_{ io_context },
          unprocessed_packets_input_{ io_context,
                                      [this](std::vector<BasePacketPtr> &packets) -> void
                                      {
                                          for (auto &packet_ptr : packets)
                                          {
                                              if (packet_ptr == nullptr)
                                              {
                                                  spdlog::warn("packet_ptr in unprocessed_input is nullptr");
                                                  continue;
                                              }
                                              auto packet_id = packet_ptr->type;
                                              auto &unprocessed_packets_queue_ = unprocessed_packets_[packet_id];
                                              unprocessed_packets_queue_.emplace_back(std::move(packet_ptr));
                                          }
                                      } },
          promise_map_input_{
              io_context,
              [this](std::vector<std::pair<UniquePacketID, shared_packet_promise>> &promise_input) -> void
              {
                  for (auto &[packet_id, shared_promise] : promise_input)
                  {
                      auto &promise_queue = promise_map_[packet_id];
                      promise_queue.emplace_back(std::move(shared_promise));
                  }
              }

          },
          promise_filter_map_input_{ io_context,
                                     [this](
                                         std::vector<std::pair<UniquePacketID, promise_filter>> &promise_input) -> void
                                     {
                                         for (auto &[packet_id, filter] : promise_input)
                                         {
                                             auto &filter_queue = promise_filter_map_[packet_id];
                                             filter_queue.emplace_back(std::move(filter));
                                         }
                                     } },
          default_handlers_input_{ io_context,
                                   [this](std::vector<std::pair<UniquePacketID, handler_tuple>> &handlers) -> void
                                   {
                                       for (auto &[packet_id, handler] : handlers)
                                       {
                                           auto &handler_list = default_handlers_[packxet_id];
                                           // Insert the handler such that filtered ones are first.
                                           mal_toolkit::SortedInsert<handler_tuple>(
                                               handler_list, std::move(handler),
                                               [](handler_tuple const &left,
                                                  handler_tuple const &right) -> bool __mal_toolkit_lambda_force_inline 
                                               {
                                                   if (bool(std::get<1>(left)))
                                                   {
                                                       return true;
                                                   }
                                                   else if (bool(std::get<1>(right)))
                                                   {
                                                       return false;
                                                   }
                                                   return true;
                                               });
                                       }
                                   } },
          subsystem_handlers_input_{ io_context,
                                     [this](std::vector<std::pair<PacketSubsystemID, handler_tuple>> &handlers) -> void
                                     {
                                         for (auto &[packet_id, handler] : handlers)
                                         {
                                             auto &handler_list = subsystem_handlers_[packet_id];
                                             // Insert the handler such that filtered ones are first.
                                             mal_toolkit::SortedInsert<handler_tuple>(
                                                 handler_list, std::move(handler),
                                                 [](handler_tuple const &left,
                                                    handler_tuple const &right) -> bool __mal_toolkit_lambda_force_inline 
                                                 {
                                                     if (bool(std::get<1>(left)))
                                                     {
                                                         return true;
                                                     }
                                                     else if (bool(std::get<1>(right)))
                                                     {
                                                         return false;
                                                     }
                                                     return true;
                                                 });
                                         }
                                     } }
    {
        spdlog::debug("PacketDispatcher constructor called.");
        co_spawn(io_context, std::bind(&PacketDispatcher::Run, this), boost::asio::detached);
    }
    void PacketDispatcher::register_subsystem_handler(PacketSubsystemID subsystem_id, PacketHandlerFunc<Packet> handler,
                                                      PacketFilterFunc<Packet> filter, float delay)
    {
        spdlog::trace("Posting task to register subsystem handler for {} subsystem", subsystem_id);
        handler_tuple tuple{ delay, std::move(filter), std::move(handler) };
        subsystem_handlers_input_.push(std::pair{ subsystem_id, std::move(tuple) });
        signal_handler_.notify();
    }

    boost::asio::awaitable<std::shared_ptr<PacketDispatcher>> PacketDispatcher::get_shared_ptr()
    {
        ExponentialBackoff backoff(std::chrono::microseconds(1), std::chrono::microseconds(100), 2, 32, 0.1);

        int it = 0;
        do
        {
            try
            {
                co_return shared_from_this();
            }
            catch (std::bad_weak_ptr &)
            {
                it++;
            }
            boost::asio::steady_timer timer(io_context_, backoff.get_current_delay());
            co_await timer.async_wait(boost::asio::use_awaitable);
            backoff.increase_delay();
            if (it >= 50 && it % 20 == 0)
            {
                spdlog::error("Failed to retrieve shared pointer, iteration: {}", it);
            }
        } while (it <= 200);
        spdlog::error("Exceeded maximum attempts to retrieve shared pointer");
        co_return nullptr;
    }
    boost::asio::awaitable<void> PacketDispatcher::Run()
    {
        SteadyTimer timer;
        float min_handler_timestamp = std::numeric_limits<float>::max();

        std::shared_ptr<PacketDispatcher> dispatcher_lock = co_await get_shared_ptr();
        if (dispatcher_lock == nullptr)
        {
            spdlog::error(
                "Couldn't retrieve shared pointer for session. Did you create the "
                "session using std::make_shared?");
            co_return;
        }
        try
        {
            while (alive_.load())
            {
                bool updated = co_await pop_inputs();

                if (!updated)
                {
                    if (min_handler_timestamp < timer.elapsed())
                    {
                        spdlog::trace("Updating handlers...");
                        min_handler_timestamp = std::numeric_limits<float>::max();

                        for (auto &[packet_id, packet_vector] : unprocessed_packets_)
                        {
                            // Remove packets that fulfill handlers and update min_handler_timestamp
                            std::erase_if(
                                packet_vector, [this, &packet_id, &min_handler_timestamp, &timer](BasePacketPtr &packet)
                                                   __mal_toolkit_lambda_force_inline 
                                { return fulfill_handlers(packet_id, packet, min_handler_timestamp, timer); });
                        }
                    }
                    co_await signal_handler_.wait_noexcept(std::chrono::microseconds(static_cast<size_t>(min_handler_timestamp * 1.0e6)));
                    continue;
                }

                spdlog::trace("Input arrays were updated! Fetching...");
                if (!alive_.load())
                {
                    break;
                }

                min_handler_timestamp = std::numeric_limits<float>::max();
                for (auto &[packet_id, packet_vector] : unprocessed_packets_)
                {
                    // Process packets: fulfill promises, fulfill handlers, and check for expiration
                    std::erase_if(packet_vector,
                                  [this, &packet_id, &min_handler_timestamp, &timer](BasePacketPtr &packet)
                                      __mal_toolkit_lambda_force_inline 
                                  {
                                      return fulfill_promises(packet_id, packet) ||
                                             fulfill_handlers(packet_id, packet, min_handler_timestamp, timer) ||
                                             packet->expired();
                                  });
                }

                // Remove empty entries from the unprocessed_packets_ map
                std::erase_if(unprocessed_packets_,
                              [](auto const &pair) __mal_toolkit_lambda_force_inline  { return pair.second.empty(); });
            }
        }
        catch (std::exception &e)
        {
            spdlog::error("PacketDispatcher::Run cancelled with an error: {}", e.what());
        }
        spdlog::info("Exiting PacketDispatcher::Run");
    }

    boost::asio::awaitable<bool> PacketDispatcher::pop_inputs()
    {
        std::vector<std::future<bool>> futures{};
        if (unprocessed_packets_input_.has_data())
        {
            futures.emplace_back(unprocessed_packets_input_.create_pop_task());
        }
        if (promise_map_input_.has_data())
        {
            futures.emplace_back(promise_map_input_.create_pop_task());
        }
        if (promise_filter_map_input_.has_data())
        {
            futures.emplace_back(promise_filter_map_input_.create_pop_task());
        }
        if (default_handlers_input_.has_data())
        {
            futures.emplace_back(default_handlers_input_.create_pop_task());
        }
        if (subsystem_handlers_input_.has_data())
        {
            futures.emplace_back(subsystem_handlers_input_.create_pop_task());
        }
        bool rv = false;
        for (auto &future : futures)
        {
            spdlog::trace("Waiting for futures to complete...");
            rv |= co_await await_future(future, co_await boost::asio::this_coro::executor);
            spdlog::trace("Futures complete. Result for popping is: {}", rv);
        }
        co_return rv;
    }
}  // namespace mal_packet_weaver