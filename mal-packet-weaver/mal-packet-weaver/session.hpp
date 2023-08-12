#pragma once
#include <algorithm>
#include <memory>
#include <mutex>
#include <queue>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/lockfree/queue.hpp>

#include "crypto/crypto.hpp"
#include "packet.hpp"
#include "mal-toolkit/mal-toolkit.hpp"
namespace mal_packet_weaver
{
    using PacketReceiverFn = std::function<void(std::unique_ptr<Packet> &&)>;
    /**
     * @brief Represents a network session for sending and receiving packets.
     * 
     * @note Session should be initialized using make_shared.
     * 
     * @details To correctly destroy this object, you need to call Destroy function, because
     * coroutines share the object from this.
     */
    class Session : public mal_toolkit::non_copyable_non_movable,
                    public std::enable_shared_from_this<Session>
    {
    public:
        /**
         * @brief Constructor for the Session class.
         *
         * @param io The boost::asio::io_context used for I/O operations.
         * @param socket The boost::asio::ip::tcp::socket associated with the session.
         */
        explicit Session(boost::asio::io_context &io, boost::asio::ip::tcp::socket &&socket);

        /**
         * @brief Destructor for the Session class.
         */
        virtual ~Session();

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
         */
        template <typename T>
        bool send_packet(const T &packet_arg) requires std::is_base_of_v<Packet, T>;

        /**
         * @brief Returns the earliest acquired packet. If packet queue is empty, returns nullptr.
         *
         * @warn If packet receiver is set through SetPacketReceiver there's no reason to call this
         * function. Generally packets will just go through the receiver. There's no ordering
         * neither option to configure which packet you will receive.
         *
         * @return std::unique_ptr<Packet>
         */
        std::unique_ptr<Packet> pop_packet_now();

        /**
         * Returns nullptr if socket has crashed.
         * If not, it will wait until the packet is available and will return it as soon as
         * possible. This function is threadsafe.
         */
        boost::asio::awaitable<std::unique_ptr<Packet>>
        pop_packet_async(boost::asio::io_context &io);

        /**
         * @brief Checks if there are packets in the queue.
         *
         * @return true if there are packets in the queue, false otherwise.
         */
        [[nodiscard]] inline bool has_packets() { return !received_packets_.empty(); }

        /**
         * @brief Checks if the session is secured using encryption.
         *
         * @return true if the session is secured, false otherwise.
         */
        [[nodiscard]] inline bool secured() const noexcept { return encryption_ != nullptr; }

        /**
         * @brief Checks if the session is closed.
         *
         * @return true if the session is closed, false otherwise.
         */
        [[nodiscard]] constexpr bool is_closed() const noexcept { return !alive_; }

        /**
         * @brief Checks if the session is alive.
         *
         * @return true if the session is alive, false otherwise.
         */
        [[nodiscard]] constexpr bool alive() const noexcept { return alive_; }

        /**
         * @brief Sets up encryption for the session using provided encryption interface.
         */
        void setup_encryption(std::shared_ptr<mal_packet_weaver::crypto::EncryptionInterface> encryption) { encryption_ = encryption; }

        /**
         * @brief Sets the packet receiver for the session.
         *
         * @param receiver The function to be called when a packet is received.
         */
        void SetPacketReceiver(PacketReceiverFn const receiver)
        {
            std::lock_guard guard{ packet_receiver_mutex_ };
            packet_receiver_ = receiver;
        }

        /**
         * @brief Coroutines use the shared pointer from this, so you need to explicitly call
         * Destroy so alive_ is false. This way coroutines can end and unlock the remaining
         * instances of shared_ptr.
         */
        void Destroy() { alive_ = false; }

    protected:
        /**
         * @brief Pops the packet data from the received packets queue.
         *
         * @details This function retrieves the data of the earliest acquired packet from the queue.
         *
         * @return A unique_ptr<ByteArray> containing the packet data, or nullptr if the queue is
         * empty.
         */
        std::unique_ptr<mal_toolkit::ByteArray> pop_packet_data() noexcept;

    private:
        /**
         * @brief Retrieves a shared pointer to the current session.
         *
         * @param io The boost::asio::io_context used for asynchronous operations.
         * @return A boost::asio::awaitable that resolves to a shared_ptr<Session>.
         */
        boost::asio::awaitable<std::shared_ptr<Session>>
        get_shared_ptr(boost::asio::io_context &io);

        /**
         * @brief Initiates an asynchronous read operation from the socket to receive data.
         *
         * @details This function asynchronously reads data from the socket into the internal
         * buffer.
         */
        void receive_all();

        /**
         * @brief Asynchronously sends all packets in the queue through the network.
         *
         * @param io The boost::asio::io_context used for asynchronous operations.
         */
        boost::asio::awaitable<void> send_all(boost::asio::io_context &io);

        /**
         * @brief Asynchronously forges new packets from the buffer.
         *
         * @param io The boost::asio::io_context used for asynchronous operations.
         */
        boost::asio::awaitable<void> async_packet_forger(boost::asio::io_context &io);
        /**
         * @brief Asynchronously receives and processes incoming packets from the network.
         *
         * @details This function continuously waits for incoming packets from the network and
         * processes them. It decrypts and deserializes encrypted packets if encryption is enabled.
         * If a valid packet receiver is set, it invokes the receiver's callback function to handle
         * the received packet.
         *
         * @param io The boost::asio::io_context used for asynchronous operations.
         */
        boost::asio::awaitable<void> async_packet_sender(boost::asio::io_context &io);
        inline void read_bytes_to(mal_toolkit::ByteArray &byte_array, const size_t amount);

        /**
         * @brief Lock-free queue to store received packets that are waiting to be processed.
         * @details Packets stored in this queue should be created using 'new'. After popping the
         * pointer, you can either delete it manually or wrap it in smart pointers. Be sure to
         * release the smart pointer before pushing it again, as failing to do so could lead to
         * undefined behavior.
         *
         * @todo Implement a circular buffer and ByteView handler for the lock-free queue.
         *       The ByteView handler should hold a simple pointer to a circular buffer and a
         * ByteView. The circular buffer should automatically free memory allocated by the
         * ByteViewHandler::free() method. This approach optimizes memory usage by avoiding repeated
         * allocation and deallocation from the OS. Another option is to use a default queue of
         * shared pointers, which automatically handles deallocation. The final choice may affect
         * performance and memory usage, and further testing is needed.
         *
         * @warning The current implementation is a proof-of-concept and has important TODOs.
         */
        boost::lockfree::queue<mal_toolkit::ByteArray *, boost::lockfree::fixed_sized<true>> received_packets_;
        /**
         * @brief Lock-free queue to store packets that are waiting to be sent.
         */
        boost::lockfree::queue<mal_toolkit::ByteArray *, boost::lockfree::fixed_sized<true>> packets_to_send_;

        /**
         * @brief Indicates whether the session is alive and operational.
         */
        bool alive_ = true;

        /**
         * @brief Buffer used for reading data from the network socket.
         */
        boost::asio::streambuf buffer_;

        /**
         * @brief The TCP socket for network communication.
         */
        boost::asio::ip::tcp::tcp::socket socket_;

        /**
         * @brief Holder for encryption using EncryptionInterface.
         */
        std::shared_ptr<mal_packet_weaver::crypto::EncryptionInterface> encryption_ = nullptr;

        /**
         * @brief Mutex to ensure thread-safe access to the packet receiver function.
         */
        std::mutex packet_receiver_mutex_;

        /**
         * @brief Callback function for processing received packets.
         */
        PacketReceiverFn packet_receiver_;
    };
} // namespace mal_packet_weaver
#include "session.inl"