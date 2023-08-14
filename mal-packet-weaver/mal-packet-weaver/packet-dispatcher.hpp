#pragma once
#include "packet.hpp"

namespace mal_packet_weaver
{
    /**
     * @brief Callback function type to handle packets asynchronously.
     *
     * This function type defines the signature for packet handler functions that accept a set of
     * arguments followed by a unique pointer to a derived packet type and return an awaitable
     * boost::asio task.
     *
     * @tparam DerivedPacket The derived packet type.
     * @tparam Args Additional argument types.
     */
    template <typename DerivedPacket, typename... Args>
    using PacketHandlerFunc = std::function<void(Args..., std::unique_ptr<DerivedPacket>)>;

    /**
     * @brief Predicate function type to filter packets.
     *
     * This function type defines the signature for packet filter functions that accept a set of
     * arguments followed by a const reference to a derived packet type and return a boolean
     * indicating whether the packet should be filtered or not.
     *
     * @tparam DerivedPacket The derived packet type.
     * @tparam Args Additional argument types.
     */
    template <typename DerivedPacket, typename... Args>
    using PacketFilterFunc = std::function<bool(Args..., DerivedPacket const &)>;

    /**
     * @brief The PacketDispatcher class is responsible for managing packet dispatching and
     * handling.
     *
     * This class associates with a specific io_context and provides functionality for enqueuing
     * packets and managing packet handlers and filters.
     *
     * @note Session should be initialized using make_shared.
     *
     * @details To correctly destroy this object, you need to call Destroy function, because
     * coroutines share the object from this.
     */
    class PacketDispatcher final : public non_copyable_non_movable,
                                   public std::enable_shared_from_this<PacketDispatcher>
    {
    public:
        /**
         * @brief Alias for a unique pointer to a base packet type.
         */
        using BasePacketPtr = std::unique_ptr<Packet>;

        /**
         * @brief Alias for a shared promise of type T.
         *
         * This type alias defines a shared pointer to a promise that holds a value of type T.
         *
         * @tparam T The type of the value held by the promise.
         */
        template <typename T>
        using shared_promise = std::shared_ptr<std::promise<T>>;

        /**
         * @brief Alias for a shared promise of a base packet pointer.
         */
        using shared_packet_promise = shared_promise<BasePacketPtr>;

        /**
         * @brief Alias for a filter function paired with a shared packet promise.
         *
         * This type alias defines a pair where the first element is a filter function that accepts
         * a const reference to a base packet pointer and returns a boolean. The second element is a
         * shared promise that holds a base packet pointer.
         */
        using promise_filter = std::pair<std::function<bool(BasePacketPtr const &)>, shared_packet_promise>;

        /**
         * @brief Alias for a tuple containing information for packet handling.
         *
         * This type alias defines a tuple that holds information related to packet handling. The
         * first element is a float representing a priority, the second element is a packet filter
         * function, and the third element is a packet handler function.
         *
         */
        using handler_tuple = std::tuple<float, PacketFilterFunc<Packet>, PacketHandlerFunc<Packet>>;

        /**
         * @brief Constructs a PacketDispatcher instance associated with the given io_context.
         *
         * @param io_context The io_context to associate with the dispatcher.
         */
        PacketDispatcher(boost::asio::io_context &io_context);

        /**
         * @brief Enqueues a packet for processing.
         *
         * This function enqueues a unique pointer to a packet for processing by pushing it onto the
         * internal queue.
         *
         * @param packet The unique pointer to the packet to be enqueued.
         */
        inline void enqueue_packet(BasePacketPtr &&packet);
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
        boost::asio::awaitable<std::unique_ptr<DerivedPacket>> await_packet(float timeout = -1.0f);
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
                                                                            float timeout = -1.0f);
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
        void register_default_handler(PacketHandlerFunc<DerivedPacket> handler,
                                      PacketFilterFunc<DerivedPacket> filter = {}, float delay = 0.0f);

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
        inline void enqueue_promise(UniquePacketID packet_id, shared_packet_promise promise);
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
        inline void enqueue_filter_promise(UniquePacketID packet_id, promise_filter filtered_promise);

        /**
         * @brief Coroutines use the shared pointer from this, so you need to explicitly call
         * Destroy so alive_ is false. This way coroutines can end and unlock the remaining
         * instances of shared_ptr.
         */
        void Destroy() { alive_.store(false); }

    private:
        /**
         * @brief Retrieves a shared pointer to the current dispatcher.
         *
         * @param io The boost::asio::io_context used for asynchronous operations.
         * @return A boost::asio::awaitable that resolves to a shared_ptr<PacketDispatcher>.
         */
        boost::asio::awaitable<std::shared_ptr<PacketDispatcher>> get_shared_ptr();

        /**
         * @brief This function represents the main loop for running a task with exponential backoff
         * and asynchronous I/O. It processes input packets and handles them while managing delays
         * and timers.
         *
         * @return A boost::asio::awaitable<void> representing the asynchronous task.
         */
        boost::asio::awaitable<void> Run();

        /**
         * @brief Fulfills promises associated with a packet ID.
         *
         * This function fulfills promises from two different maps: promise_filter_map_
         * and promise_map_. It searches for promises in promise_filter_map_ first,
         * and if a matching promise is found, it checks if the associated filter
         * condition (if any) is satisfied before fulfilling the promise. If no matching
         * promise is found in promise_filter_map_, it then searches for a promise in
         * promise_map_ and fulfills the first one if available.
         *
         * @param packet_id The unique ID of the packet.
         * @param packet A reference to the packet to be fulfilled.
         * @return `true` if at least one promise was fulfilled, otherwise `false`.
         */
        inline bool fulfill_promises(UniquePacketID packet_id, BasePacketPtr &packet);

        /**
         * @brief Fulfills handlers associated with a packet ID and packet data.
         *
         * This function fulfills handlers for a given packet ID by searching for
         * associated handlers in the default_handlers_ map. For each handler,
         * it checks if the specified delay is greater than the packet's time alive.
         * If so, it updates the minimum handler timestamp. Then, it checks if the
         * associated filter condition (if any) is satisfied before executing the handler.
         *
         * @param packet_id The unique ID of the packet.
         * @param packet A reference to the packet for which handlers should be fulfilled.
         * @param min_handler_timestamp The minimum handler timestamp to update.
         * @param timer The timer used for timestamp calculations.
         * @return `true` if at least one handler was fulfilled, otherwise `false`.
         */
        inline bool fulfill_handlers(UniquePacketID packet_id, BasePacketPtr &packet, float &min_handler_timestamp,
                                     SteadyTimer &timer);

        /**
         * @brief Pushes an input packet to the unprocessed_packets_input_ queue.
         *
         * This function posts a task to the unprocessed_packets_input_strand_
         * to push an input packet into the unprocessed_packets_input_ queue. The
         * packet is moved into a unique pointer, and the unprocessed_packets_input_updated_
         * atomic flag is set to indicate that the queue has been updated.
         *
         * @param packet The packet to push (as an rvalue reference).
         */
        inline void push_packet(BasePacketPtr &&packet);
        /**
         * @brief Creates a promise_map_input_pop_task and returns a future to await completion.
         * @return A future that signals the completion of the task.
         */
        std::future<bool> create_promise_map_input_pop_task();

        /**
         * @brief Creates a promise_filter_map_input_pop_task and returns a future to await
         * completion.
         * @return A future that signals the completion of the task.
         */
        std::future<bool> create_promise_filter_map_input_pop_task();

        /**
         * @brief Creates a default_handlers_input_pop_task and returns a future to await
         * completion.
         * @return A future that signals the completion of the task.
         */
        std::future<bool> create_default_handlers_input_pop_task();

        /**
         * @brief Creates an unprocessed_packets_input_pop_task and returns a future to await
         * completion.
         * @return A future that signals the completion of the task.
         */
        std::future<bool> create_unprocessed_packets_input_pop_task();

        /**
         * @brief Pops input packets from input queues to local maps for processing.
         * @return An awaitable indicating whether the task was successful.
         */
        boost::asio::awaitable<bool> pop_inputs();

        boost::asio::io_context &io_context_; /**< Reference to the associated Boost.Asio io_context. */

        boost::asio::io_context::strand unprocessed_packets_input_strand_; /**< Strand for synchronizing access to the
                                                                              unprocessed input packets queue. */
        boost::asio::io_context::strand promise_map_input_strand_; /**< Strand for synchronizing access to the promise
                                                                      map input. */
        boost::asio::io_context::strand promise_filter_map_input_strand_; /**< Strand for synchronizing access to the
                                                                             promise filter map input. */
        boost::asio::io_context::strand default_handlers_input_strand_;   /**< Strand for synchronizing access to the
                                                                             default   handlers input. */

        std::atomic_flag unprocessed_packets_input_updated_; /**< Atomic flag indicating updates to
                                                                unprocessed_packets_input_. */
        std::atomic_flag promise_map_input_updated_;         /**< Atomic flag indicating updates to
                                                                promise_map_input_. */
        std::atomic_flag promise_filter_map_input_updated_;  /**< Atomic flag indicating updates to
                                                                promise_filter_map_input_. */
        std::atomic_flag default_handlers_input_updated_;    /**< Atomic flag indicating updates to
                                                                default_handlers_input_. */

        std::vector<BasePacketPtr> unprocessed_packets_input_; /**< Queue for storing unprocessed input packets. */
        std::vector<std::pair<UniquePacketID, shared_packet_promise>>
            promise_map_input_; /**< Queue for storing promise map inputs. */
        std::vector<std::pair<UniquePacketID, promise_filter>>
            promise_filter_map_input_; /**< Queue for storing promise filter map inputs. */
        std::vector<std::pair<UniquePacketID, handler_tuple>>
            default_handlers_input_; /**< Queue for storing default handlers inputs. */

        std::unordered_map<UniquePacketID, std::vector<BasePacketPtr>>
            unprocessed_packets_; /**< Map storing unprocessed packets for each packet ID. */
        std::unordered_map<UniquePacketID, std::deque<shared_packet_promise>>
            promise_map_; /**< Map storing promises for each packet ID. */
        std::unordered_map<UniquePacketID, std::vector<promise_filter>>
            promise_filter_map_; /**< Map storing promise filters for each packet ID. */
        std::unordered_map<UniquePacketID, std::vector<handler_tuple>>
            default_handlers_; /**< Map storing default packet handlers for each packet ID. */

        std::atomic_bool alive_{ true };
    };
}  // namespace mal_packet_weaver

#include "packet-dispatcher.inl"