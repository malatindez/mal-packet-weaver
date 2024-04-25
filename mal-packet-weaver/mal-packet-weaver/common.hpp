#pragma once
#if defined(_WIN32)
#include <SDKDDKVer.h>
#endif
#include <algorithm>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/bind/bind.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/thread.hpp>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>

#include <cereal/cereal.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/map.hpp>
#include <cereal/archives/portable_binary.hpp>

#include "mal-toolkit/mal-toolkit.hpp"
/**
 * @brief This is the main namespace for the Mal Packet Weaver library.
 *
 * This namespace encapsulates the functionality of the Mal Packet Weaver
 * library, which includes tools for working with packets and networking.
 */
namespace mal_packet_weaver
{
    class timeout_exception : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };
    class future_failed : public std::runtime_error
    {
        public:
        using std::runtime_error::runtime_error;
    };
    /**
     * @brief This namespace alias brings symbols from the mal_toolkit namespace
     * into mal_packet_weaver.
     *
     * By using this namespace alias, symbols from the mal_toolkit namespace become
     * accessible within the mal_packet_weaver namespace without needing to prefix
     * them with . This can help improve code readability and simplify usage.
     */
    using namespace mal_toolkit;
// clang-format off
    namespace _await_future_impl
    {
        template <typename T, typename ChronoType, typename Executor>
        boost::asio::awaitable<T> await_future(Executor &executor, std::future<T>& fut, ChronoType timeout)
        {
            auto timer = std::shared_ptr<boost::asio::steady_timer>{
                new boost::asio::steady_timer{executor, timeout}
            };
            static boost::thread::attributes attrs;
            attrs.set_stack_size(4096 * 8);  // 32 Kb per thread
            if constexpr (std::is_same_v<T, void>)
            {
                if (fut.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
                {
                    co_return;
                }
                boost::thread thread(attrs,
                                     [timer, &fut]()
                                     {
                                         try { fut.wait(); timer->cancel(); }
    #ifdef _DEBUG
                                         catch (std::exception& e) { spdlog::error("Future failed with exception: {}", e.what()); }
    #endif
                                         catch (...) { timer->cancel(); }
                                     });
                thread.detach();
                try { co_await timer->async_wait(boost::asio::use_awaitable);} 
                catch(...) { }
                co_return;
            }
            else
            {
                if (fut.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
                {
                    co_return fut.get();
                }
                auto result = std::make_shared<std::optional<T>>(std::nullopt);
                boost::thread thread(attrs,
                                     [timer = timer, result = result, &fut]()
                                     {
                                         try { fut.wait(); *result = fut.get(); timer->cancel(); }
    #ifdef _DEBUG
                                         catch (std::exception& e) { spdlog::error("Future failed with exception: {}", e.what()); }
    #endif
                                         catch (...) { timer->cancel(); }
                                     });
                thread.detach();
                try { co_await timer->async_wait(boost::asio::use_awaitable); }
                catch(std::exception &e) { }
                if (*result == std::nullopt) { throw future_failed{"Future failed for unknown reason."}; }
                co_return std::move(result->value());
            }
        }
    }
    template <typename T,  typename Executor>
    boost::asio::awaitable<T> await_future(Executor& executor, std::future<T>& fut)
    {
        return _await_future_impl::await_future(executor, fut, std::chrono::steady_clock::time_point::max());
    }
    
    template <typename T, typename ChronoType,  typename Executor>
    boost::asio::awaitable<T> await_future(Executor& executor, std::future<T>& fut, ChronoType timeout)
    {
        return _await_future_impl::await_future(executor, fut, timeout);
    }
// clang-format on

    class SignalHandler {
    public:
        SignalHandler(boost::asio::io_context& io_context) : io_context_(io_context) {}

        // Asynchronously wait for the signal
        boost::asio::awaitable<void> wait()
        {
            auto timer = std::make_shared<boost::asio::steady_timer>(co_await boost::asio::this_coro::executor,
                                                                     std::chrono::steady_clock::time_point::max());
            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.emplace_back(timer);
            }
            try
            {
                co_await timer->async_wait(boost::asio::use_awaitable);
            }
            catch(...) {}
        }
        // Asynchronously wait for the signal
        template <typename ChronoType>
        boost::asio::awaitable<void> wait(ChronoType timeout)
        {
            auto timer = std::make_shared<boost::asio::steady_timer>(co_await boost::asio::this_coro::executor, 
                                                                     timeout);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.emplace_back(timer);
            }
            try
            {
                co_await timer->async_wait(boost::asio::use_awaitable);
            }
            catch (...) { }
        }

        // Notify all waiters
        void notify() {
            std::deque<std::shared_ptr<boost::asio::steady_timer>> waiters;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiters_.swap(waiters);
            }
            for (auto& waiter : waiters) {
                waiter->cancel();
            }
        }

    private:
        boost::asio::io_context& io_context_;
        std::mutex mutex_;
        std::deque<std::shared_ptr<boost::asio::steady_timer>> waiters_;
    };

}  // namespace mal_packet_weaver
