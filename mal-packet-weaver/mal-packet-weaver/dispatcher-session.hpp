#pragma once
#include "packet-dispatcher.hpp"
#include "session.hpp"
namespace mal_packet_weaver
{
    /**
     * @class DispatcherSession
     * @brief Represents a session with packet dispatching functionality.
     */
    class DispatcherSession
    {
    public:
        /**
         * @brief Constructor for DispatcherSession.
         * @param io_context The IO context to use for the session.
         * @param socket The TCP socket to use for the session.
         */
        DispatcherSession(boost::asio::io_context &io_context, boost::asio::ip::tcp::socket &&socket)
            : session_{ std::make_shared<Session>(io_context, std::move(socket)) },
              dispatcher_{ std::make_shared<PacketDispatcher>(io_context) }
        {
        }

        /**
         * @brief Destructor for DispatcherSession.
         * Cleans up the session and packet dispatcher.
         */
        ~DispatcherSession()
        {
            session_->Destroy();
            dispatcher_->Destroy();
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
        inline boost::asio::awaitable<std::unique_ptr<Packet>> pop_packet_async(boost::asio::io_context &io)
        {
            co_return session_->pop_packet_async(io);
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
        inline void enqueue_packet(BasePacketPtr &&packet) { dispatcher_->enqueue_packet(std::move(packet)); }

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
            co_return dispatcher_->await_packet(timeout);
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
            co_return dispatcher_->await_packet(filter, timeout);
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
         * @brief Enqueues a promise associated with a packet.
         *
         * This function enqueues a promise (associated with a specific packet ID) for future
         * fulfillment. The promise is associated with a unique packet identifier. The enqueued
         * promises will be processed later.
         *
         * @param packet_id The unique packet identifier for which the promise is being enqueued.
         * @param promise The shared packet promise to be enqueued.
         */
        inline void enqueue_promise(UniquePacketID packet_id, shared_packet_promise promise)
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
        inline void enqueue_filter_promise(UniquePacketID packet_id, promise_filter filtered_promise)
        {
            return dispatcher_->enqueue_filter_promise(packet_id, filtered_promise);
        }

        /**
         * @brief Get a reference to the underlying session.
         * @return A reference to the session.
         */
        [[nodiscard]] constexpr Session &session() { return *session_; }

        /**
         * @brief Get a reference to the underlying packet dispatcher.
         * @return A reference to the packet dispatcher.
         */
        [[nodiscard]] constexpr PacketDispatcher &dispatcher_() { return *dispatcher_; }

    private:
        std::shared_ptr<Session> session_;              ///< The underlying session.
        std::shared_ptr<PacketDispatcher> dispatcher_;  ///< The underlying packet dispatcher.
    };
}  // namespace mal_packet_weaver