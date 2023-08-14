#pragma once
#include "packet-dispatcher.hpp"
#include "session.hpp"
namespace mal_packet_weaver
{
    /**
     * @class DispatcherSession
     * @brief Represents a session with packet dispatching functionality.
     */
    class DispatcherSession final
    {
    public:
        /**
         * @brief Constructor for DispatcherSession.
         * @param io_context The IO context to use for the session.
         * @param socket The TCP socket to use for the session.
         */
        DispatcherSession(boost::asio::io_context &io_context, boost::asio::ip::tcp::socket &&socket)
            : io_context_{ io_context },
              session_{ std::make_shared<Session>(io_context, std::move(socket)) },
              dispatcher_{ std::make_shared<PacketDispatcher>(io_context) }
        {
            session_->set_packet_receiver(
                [&dispatcher_ = *dispatcher_](std::unique_ptr<mal_packet_weaver::Packet> &&packet) __lambda_force_inline
                { dispatcher_.enqueue_packet(std::move(packet)); });
        }
        DispatcherSession(DispatcherSession const &) = delete;
        DispatcherSession &operator=(DispatcherSession const &) = delete;
        DispatcherSession(DispatcherSession &&) = delete;
        DispatcherSession &operator=(DispatcherSession &&) = delete;

        /**
         * @brief Destructor for DispatcherSession.
         * Cleans up the session and packet dispatcher.
         */
        ~DispatcherSession()
        {
            if (session_ != nullptr)
            {
                session_->Destroy();
            }
            if (dispatcher_ != nullptr)
            {
                dispatcher_->Destroy();
            }
        }

        /**
         * @brief Sends any packet derived from DerivedPacket through the network.
         *
         * @tparam T Final packet type.
         * (Template functions cannot be overriden, we need to call serialize from the furthest
         * child.)
         *
         * @note Blockable until packets_to_send_ can retrieve the value.
         *
         * @param packet_arg Packet value
         * @return true if session got the packet.
         * @return false if session was closed.
         * @see Session::send_packet
         */
        template <typename T>
        inline bool send_packet(const T &packet_arg) requires std::is_base_of_v<Packet, T>
        {
            return session_->send_packet(packet_arg);
        }

        /**
         * @brief Returns the earliest acquired packet. If packet queue is empty, returns nullptr.
         *
         * @warning If packet receiver is set through SetPacketReceiver there's no reason to call this
         * function. Generally packets will just go through the receiver. There's no ordering
         * neither option to configure which packet you will receive.
         *
         * @return std::unique_ptr<Packet>
         * @see Session::pop_packet_now
         */
        inline std::unique_ptr<Packet> pop_packet_now() { return session_->pop_packet_now(); }

        /**
         * Returns nullptr if socket has crashed.
         * If not, it will wait until the packet is available and will return it as soon as
         * possible. This function is threadsafe.
         * @see Session::pop_packet_async
         */
        inline boost::asio::awaitable<std::unique_ptr<Packet>> pop_packet_async()
        {
            auto value = co_await session_->pop_packet_async(io_context_);
            co_return std::move(value);
        }

        /**
         * @brief Checks if there are packets in the queue.
         *
         * @return true if there are packets in the queue, false otherwise.
         * @see Session::has_packets
         */
        [[nodiscard]] inline bool has_packets() { return session_->has_packets(); }

        /**
         * @brief Checks if the session is secured using encryption.
         *
         * @return true if the session is secured, false otherwise.
         * @see Session::secured
         */
        [[nodiscard]] inline bool secured() const noexcept { return session_->secured(); }

        /**
         * @brief Checks if the session is closed.
         *
         * @return true if the session is closed, false otherwise.
         * @see Session::is_closed
         */
        [[nodiscard]] constexpr bool is_closed() const noexcept { return session_->is_closed(); }

        /**
         * @brief Checks if the session is alive.
         *
         * @return true if the session is alive, false otherwise.
         * @see Session::alive
         */
        [[nodiscard]] constexpr bool alive() const noexcept { return session_->alive(); }

        /**
         * @brief Sets up encryption for the session using provided encryption interface.
         * @see Session::setup_encryption
         */
        inline void setup_encryption(std::shared_ptr<mal_packet_weaver::crypto::EncryptionInterface> encryption)
        {
            session_->setup_encryption(encryption);
        }

        /**
         * @brief Sets the packet receiver for the session.
         *
         * @param receiver The function to be called when a packet is received.
         * @see Session::set_packet_receiver
         */
        inline void set_packet_receiver(PacketReceiverFn const receiver) { session_->set_packet_receiver(receiver); }

        /**
         * @brief Enqueues a packet for processing.
         *
         * This function enqueues a unique pointer to a packet for processing by pushing it onto the
         * internal queue.
         *
         * @param packet The unique pointer to the packet to be enqueued.
         */
        inline void enqueue_packet(PacketDispatcher::BasePacketPtr &&packet)
        {
            dispatcher_->enqueue_packet(std::move(packet));
        }

        /**
         * @brief Wait until the packet is registered in the dispatch system and return as soon as
         * possible.
         *
         * This function template waits for a specific type of packet to be registered in the
         * dispatch system. It can optionally wait for a specified timeout duration.
         *
         * @tparam DerivedPacket The type of packet you want to wait for.
         * @param timeout If less than or equal to zero, the function will not return until the
         * promise is fulfilled. Otherwise, it will wait for the given timeout (in seconds) before
         * returning.
         * @return boost::asio::awaitable<std::unique_ptr<DerivedPacket>> A unique pointer to the
         * received packet, or nullptr if the timeout was reached.
         */
        template <IsPacket DerivedPacket>
        boost::asio::awaitable<std::unique_ptr<DerivedPacket>> await_packet(float timeout = -1.0f)
        {
            return dispatcher_->await_packet<DerivedPacket>(timeout);
        }

        /**
         * @brief Wait until a packet satisfying the filter condition is registered in the dispatch
         * system and return as soon as possible.
         *
         * This function template waits for a packet of a specific type, satisfying a provided
         * filter condition, to be registered in the dispatch system. It can optionally wait for a
         * specified timeout duration.
         *
         * @tparam DerivedPacket The type of packet you want to wait for.
         * @param filter A function to filter the packet. If the functor returns true, the packet
         * will fulfill the promise.
         * @param timeout If less than or equal to zero, the function will not return until the
         * promise is fulfilled. Otherwise, it will wait for the given timeout (in seconds) before
         * returning.
         * @return boost::asio::awaitable<std::unique_ptr<DerivedPacket>> A unique pointer to the
         * received packet, or nullptr if the timeout was reached or the filter condition was not
         * satisfied.
         */
        template <IsPacket DerivedPacket>
        boost::asio::awaitable<std::unique_ptr<DerivedPacket>> await_packet(PacketFilterFunc<DerivedPacket> filter,
                                                                            float timeout = -1.0f)
        {
            return dispatcher_->await_packet<DerivedPacket>(filter, timeout);
        }

        /**
         * @brief Registers a default handler for the provided packet type.
         *
         * This function registers a default packet handler for a specific packet type. The handler
         * function can be provided, and if it returns false, the packet is passed to the next
         * handler. An optional filter function can also be provided to determine whether the
         * handler should be applied based on the packet's properties. A delay parameter can be used
         * to postpone the handler's execution for a certain amount of time.
         *
         * @todo Add an ability to delete handlers
         *
         * @tparam DerivedPacket The type of packet for which the handler should be registered.
         * @param handler The packet handler function. If it returns false, the packet will be
         * passed to the next handler.
         * @param filter The packet filter function to determine whether the handler should be
         * applied. (Optional)
         * @param delay The delay in seconds before the handler is executed. (Default is 0.0)
         */
        template <IsPacket DerivedPacket>
        inline void register_default_handler(PacketHandlerFunc<DerivedPacket> handler,
                                             PacketFilterFunc<DerivedPacket> filter = {}, float delay = 0.0f)
        {
            return dispatcher_->register_default_handler(handler, filter, delay);
        }
        /**
         * @brief Register a default handler for the provided packet type.
         *
         * This function registers a default packet handler for a specific packet type. The handler
         * function can be provided, and if it returns false, the packet is passed to the next
         * handler. An optional filter function can also be provided to determine whether the
         * handler should be applied based on the packet's properties. A delay parameter can be used
         * to postpone the handler's execution for a certain amount of time.
         *
         * @tparam Arg1 The type of argument 1 for the handler.
         * @tparam Args Additional argument types for the handler.
         * @tparam CustomPacket The type of packet for which the handler should be registered.
         * @param handler The packet handler function.
         * @param filter The packet filter function to determine whether the handler should be applied.
         * @param delay The delay in seconds before the handler is executed. (Default is 0.0)
         *
         * @note Supported types for Args are: Session&, std::shared_ptr<Session>, io_context &,
         *       std::shared_ptr<PacketDispatcher>, and PacketDispatcher&. The std::unique_ptr<CustomPacket> type should
         * be last.
         */
        template <typename Arg1, IsPacket CustomPacket>
        inline void register_default_handler(PacketHandlerFunc<CustomPacket, Arg1> &&handler,
                                             PacketFilterFunc<CustomPacket, Arg1> &&filter = {}, float delay = 0.0f)
        {
            if constexpr (std::is_same_v<Arg1, std::shared_ptr<Session>>)
            {
                return register_default_handler<CustomPacket>(
                    [session_ = std::weak_ptr<Session>(session_), moved_handler = std::move(handler)](
                        std::unique_ptr<CustomPacket> &&packet) { moved_handler(session_.lock(), std::move(packet)); },
                    (bool(filter) ? ([session_ = std::weak_ptr<Session>(session_), moved_filter = std::move(filter)](
                                         const CustomPacket &packet) { return moved_filter(session_.lock(), packet); })
                                  : PacketFilterFunc<CustomPacket>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, Session &>)
            {
                return register_default_handler<CustomPacket>(
                    [session_ = std::weak_ptr<Session>(session_), moved_handler = std::move(handler)](
                        std::unique_ptr<CustomPacket> &&packet) { moved_handler(*session_.lock(), std::move(packet)); },
                    (bool(filter) ? ([session_ = std::weak_ptr<Session>(session_), moved_filter = std::move(filter)](
                                         const CustomPacket &packet) { return moved_filter(*session_.lock(), packet); })
                                  : PacketFilterFunc<CustomPacket>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, boost::asio::io_context &>)
            {
                return register_default_handler<CustomPacket>(
                    [io_context_ = std::ref(io_context_), moved_handler = std::move(handler)](
                        std::unique_ptr<CustomPacket> &&packet) { moved_handler(io_context_, std::move(packet)); },
                    (bool(filter) ? ([io_context_ = std::ref(io_context_), moved_filter = std::move(filter)](
                                         const CustomPacket &packet) { return moved_filter(io_context_, packet); })
                                  : PacketFilterFunc<CustomPacket>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, std::shared_ptr<PacketDispatcher>>)
            {
                return register_default_handler<CustomPacket>(
                    [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                     moved_handler = std::move(handler)](std::unique_ptr<CustomPacket> &&packet)
                    { moved_handler(dispatcher_.lock(), std::move(packet)); },
                    (bool(filter) ? ([dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                                      moved_filter = std::move(filter)](const CustomPacket &packet)
                                     { return moved_filter(dispatcher_.lock(), packet); })
                                  : PacketFilterFunc<CustomPacket>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, PacketDispatcher &>)
            {
                return register_default_handler<CustomPacket>(
                    [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                     moved_handler = std::move(handler)](std::unique_ptr<CustomPacket> &&packet)
                    { moved_handler(*dispatcher_.lock(), std::move(packet)); },
                    (bool(filter) ? ([dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                                      moved_filter = std::move(filter)](const CustomPacket &packet)
                                     { return moved_filter(*dispatcher_.lock(), packet); })
                                  : PacketFilterFunc<CustomPacket>{}),
                    delay);
            }
            else
            {
                []<bool flag = false>()
                {
                    static_assert(flag,
                                  "Unknown type passed! Supported types for handler are: Session&, "
                                  "std::shared_ptr<Session>, io_context &, std::shared_ptr<PacketDispatcher> and "
                                  "PacketDispatcher&. The CustomPacket type should be last.");
                }
                ();
            }
        }

        /**
         * @brief Register a default handler for the provided packet type.
         *
         * This function registers a default packet handler for a specific packet type. The handler
         * function can be provided, and if it returns false, the packet is passed to the next
         * handler. An optional filter function can also be provided to determine whether the
         * handler should be applied based on the packet's properties. A delay parameter can be used
         * to postpone the handler's execution for a certain amount of time.
         *
         * @tparam Arg1 The type of argument 1 for the handler.
         * @tparam Arg2 The type of argument 2 for the handler.
         * @tparam Args Additional argument types for the handler.
         * @tparam CustomPacket The type of packet for which the handler should be registered.
         * @param handler The packet handler function.
         * @param filter The packet filter function to determine whether the handler should be applied.
         * @param delay The delay in seconds before the handler is executed. (Default is 0.0)
         *
         * @note Supported types for Args are: Session&, std::shared_ptr<Session>, io_context &,
         *       std::shared_ptr<PacketDispatcher>, and PacketDispatcher&. The std::unique_ptr<CustomPacket> type should
         * be last.
         */
        template <typename Arg1, typename Arg2, typename... Args, IsPacket CustomPacket>
        inline void register_default_handler(PacketHandlerFunc<CustomPacket, Arg1, Arg2, Args...> &&handler,
                                             PacketFilterFunc<CustomPacket, Arg1, Arg2, Args...> &&filter = {},
                                             float delay = 0.0f)
        {
            if constexpr (std::is_same_v<Arg1, std::shared_ptr<Session>>)
            {
                return register_default_handler<Arg2, Args..., CustomPacket>(
                    [session_ = std::weak_ptr<Session>(session_), moved_handler = std::move(handler)](
                        Arg2 &&arg2, Args &&...args, std::unique_ptr<CustomPacket> &&packet) {
                        moved_handler(session_.lock(), std::forward<Arg2>(arg2), std::forward<Args>(args)...,
                                      std::move(packet));
                    },
                    (bool(filter) ? (
                                        [session_ = std::weak_ptr<Session>(session_), moved_filter = std::move(filter)](
                                            Arg2 &&arg2, Args &&...args, const CustomPacket &packet) {
                                            return moved_filter(session_.lock(), std::forward<Arg2>(arg2),
                                                                std::forward<Args>(args)..., packet);
                                        })
                                  : PacketFilterFunc<CustomPacket, Arg2, Args...>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, Session &>)
            {
                return register_default_handler<Arg2, Args..., CustomPacket>(
                    [session_ = std::weak_ptr<Session>(session_), moved_handler = std::move(handler)](
                        Arg2 &&arg2, Args &&...args, std::unique_ptr<CustomPacket> &&packet) {
                        moved_handler(*session_.lock(), std::forward<Arg2>(arg2), std::forward<Args>(args)...,
                                      std::move(packet));
                    },
                    (bool(filter) ? (
                                        [session_ = std::weak_ptr<Session>(session_), moved_filter = std::move(filter)](
                                            Arg2 &&arg2, Args &&...args, const CustomPacket &packet) {
                                            return moved_filter(*session_.lock(), std::forward<Arg2>(arg2),
                                                                std::forward<Args>(args)..., packet);
                                        })
                                  : PacketFilterFunc<CustomPacket, Arg2, Args...>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, boost::asio::io_context &>)
            {
                return register_default_handler<Arg2, Args..., CustomPacket>(
                    [io_context_ = std::ref(io_context_), moved_handler = std::move(handler)](
                        Arg2 &&arg2, Args &&...args, std::unique_ptr<CustomPacket> &&packet) {
                        moved_handler(io_context_, std::forward<Arg2>(arg2), std::forward<Args>(args)...,
                                      std::move(packet));
                    },
                    (bool(filter) ? (
                                        [io_context_ = std::ref(io_context_), moved_filter = std::move(filter)](
                                            Arg2 &&arg2, Args &&...args, const CustomPacket &packet) {
                                            return moved_filter(io_context_, std::forward<Arg2>(arg2),
                                                                std::forward<Args>(args)..., packet);
                                        })
                                  : PacketFilterFunc<CustomPacket, Arg2, Args...>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, std::shared_ptr<PacketDispatcher>>)
            {
                return register_default_handler<Arg2, Args..., CustomPacket>(
                    [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_), moved_handler = std::move(handler)](
                        Arg2 &&arg2, Args &&...args, std::unique_ptr<CustomPacket> &&packet) {
                        moved_handler(dispatcher_.lock(), std::forward<Arg2>(arg2), std::forward<Args>(args)...,
                                      std::move(packet));
                    },
                    (bool(filter)
                         ? (
                               [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                                moved_filter = std::move(filter)](Arg2 &&arg2, Args &&...args, const CustomPacket &) {
                                   return moved_filter(dispatcher_.lock(), std::forward<Arg2>(arg2),
                                                       std::forward<Args>(args)..., packet);
                               })
                         : PacketFilterFunc<CustomPacket, Arg2, Args...>{}),
                    delay);
            }
            else if constexpr (std::is_same_v<Arg1, PacketDispatcher &>)
            {
                return register_default_handler<Arg2, Args..., CustomPacket>(
                    [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_), moved_handler = std::move(handler)](
                        Arg2 &&arg2, Args &&...args, std::unique_ptr<CustomPacket> &&packet) {
                        moved_handler(*dispatcher_.lock(), std::forward<Arg2>(arg2), std::forward<Args>(args)...,
                                      std::move(packet));
                    },
                    (bool(filter)
                         ? (
                               [dispatcher_ = std::weak_ptr<PacketDispatcher>(dispatcher_),
                                moved_filter = std::move(filter)](Arg2 &&arg2, Args &&...args, const CustomPacket &) {
                                   return moved_filter(*dispatcher_.lock(), std::forward<Arg2>(arg2),
                                                       std::forward<Args>(args)..., packet);
                               })
                         : PacketFilterFunc<CustomPacket, Arg2, Args...>{}),
                    delay);
            }
            else
            {
                []<bool flag = false>()
                {
                    static_assert(flag,
                                  "Unknown type passed! Supported types for handler are: Session&, "
                                  "std::shared_ptr<Session>, io_context &, std::shared_ptr<PacketDispatcher> and "
                                  "PacketDispatcher&. The CustomPacket type should be last.");
                }
                ();
            }
        }

        template <IsPacket CustomPacket, typename... FnArgs>
        inline void register_default_handler(std::function<void(FnArgs...)> &&handler,
                                             std::function<bool(FnArgs...)> &&filter = {}, float delay = 0.0f)
        {
            return register_default_handler<FnArgs..., CustomPacket>(handler, filter, delay);
        }
        /**
         * @brief Enqueues a promise associated with a packet.
         *
         * This function enqueues a promise (associated with a specific packet ID) for future
         * fulfillment. The promise is associated with a unique packet identifier. The enqueued
         * promises will be processed later.
         *
         * @param packet_id The unique packet identifier for which the promise is being enqueued.
         * @param promise The shared packet promise to be enqueued.
         */
        inline void enqueue_promise(UniquePacketID packet_id, PacketDispatcher::shared_packet_promise promise)
        {
            return dispatcher_->enqueue_promise(packet_id, promise);
        }

        /**
         * @brief Enqueues a promise with a filter associated with a packet.
         *
         * This function enqueues a promise (associated with a specific packet ID) that includes a
         * filter function. The promise will be fulfilled based on the provided filter's outcome.
         * The enqueued promises with filters will be processed later.
         *
         * @param packet_id The unique packet identifier for which the filtered promise is being
         * enqueued.
         * @param filtered_promise The promise filter to be enqueued.
         */
        inline void enqueue_filter_promise(UniquePacketID packet_id, PacketDispatcher::promise_filter filtered_promise)
        {
            return dispatcher_->enqueue_filter_promise(packet_id, filtered_promise);
        }

        /**
         * @brief Get a reference to the underlying session.
         * @return A reference to the session.
         */
        [[nodiscard]] inline Session &session() { return *session_; }

        /**
         * @brief Get a reference to the underlying packet dispatcher.
         * @return A reference to the packet dispatcher.
         */
        [[nodiscard]] inline PacketDispatcher &dispatcher() { return *dispatcher_; }

        void Destroy()
        {
            session_->Destroy();
            dispatcher_->Destroy();
        }

    private:
        boost::asio::io_context &io_context_;           ///< Reference to the associated Boost.Asio io_context.
        std::shared_ptr<Session> session_;              ///< The underlying session.
        std::shared_ptr<PacketDispatcher> dispatcher_;  ///< The underlying packet dispatcher.
    };
}  // namespace mal_packet_weaver