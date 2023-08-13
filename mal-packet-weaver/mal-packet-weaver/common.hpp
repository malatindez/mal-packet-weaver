#if defined(_WIN32)
#include <SDKDDKVer.h>
#endif
#include <algorithm>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind/bind.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/serialization.hpp>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

#include "mal-toolkit/mal-toolkit.hpp"

/**
 * @brief This is the main namespace for the Mal Packet Weaver library.
 *
 * This namespace encapsulates the functionality of the Mal Packet Weaver
 * library, which includes tools for working with packets and networking.
 */
namespace mal_packet_weaver
{
    /**
     * @brief This namespace alias brings symbols from the mal_toolkit namespace
     * into mal_packet_weaver.
     *
     * By using this namespace alias, symbols from the mal_toolkit namespace become
     * accessible within the mal_packet_weaver namespace without needing to prefix
     * them with . This can help improve code readability and simplify usage.
     */
    using namespace mal_toolkit;
}  // namespace mal_packet_weaver
