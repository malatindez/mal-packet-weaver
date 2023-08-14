[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct-single.svg)](https://stand-with-ukraine.pp.ua)

# MAL Packet Weaver

The MAL Packet Weaver is a C++ library that provides utilities for working with network packets. It simplifies the creation, manipulation, and serialization of network packets. The library is designed to be easy to use, efficient, and highly customizable.

- Documentation: [link](https://malatindez.github.io/mal-packet-weaver)

## Table of contents

- [Dependencies](#dependencies)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Creating a Custom Packet: MyPacket](#creating-a-custom-packet-mypacket)
    - [Declaring the Packet Type](#declaring-the-packet-type)
    - [Using Inheritance](#using-inheritance)
    - [Registering Deserializers](#registering-deserializers)
  - [Waiting for Packets with PacketDispatcher](#waiting-for-packets-with-packetdispatcher)
    - [Awaiting a Specific Packet](#awaiting-a-specific-packet)
    - [Awaiting a Packet with a Filter](#awaiting-a-packet-with-a-filter)
    - [Registering Default Handlers](#registering-default-handlers)
  - [Putting it All Together](#putting-it-all-together)
  - [Thread safety](#thread-safety)
- [Contributing](#contributing)
- [License](#license)

## Dependencies

- [Boost](https://www.boost.org/): A set of high-quality libraries for C++ programming.
- [mal-toolkit](https://github.com/malatindez/mal-toolkit): My custom C++20 toolkit library.
- [spdlog](https://github.com/gabime/spdlog): A fast C++ logging library.

## Features

- Create and manipulate network packets with ease.
- Serialize and deserialize packets using boost.
- Extensible architecture for adding custom packet types and serialization formats.
- Integration with logging through the use of spdlog.
- Provides encryption interface in [mal_packet_weaver/crypto/openssl](mal_packet_weaver/crypto/openssl) (Optional)

## Installation

1. Clone the repository:
   ```shell
   git clone https://github.com/malatindez/mal-packet-weaver.git
   ```
2. Update and initialize submodules:
   ```shell
   git submodule update --init --recursive
   ```
3. Build the library using CMake:

   ```shell
   cd mal-packet-weaver
   mkdir build
   cd build
   cmake ..
   make
   ```

4. Link the built library and its dependencies to your project.

### You can also use it as a submodule with CMake:

1. Add submodule to your repository:
   ```shell
   git submodule add https://github.com/malatindez/mal-packet-weaver.git path/to/mal-packet-weaver
   ```
2. Integrate the library into your CMake project:

   ```cmake
   add_subdirectory(path/to/mal-packet-weaver)
   target_link_libraries(your_project PRIVATE mal-packet-weaver)
   ```

3. Include the desired headers in your source files:

   ```cpp
   #include <mal-packet-weaver/.hpp>
   #include <mal-packet-weaver/packet-dispatcher.hpp>
   // ... other headers ...
   ```

# Usage

## Creating a Custom Packet: MyPacket

In this example, we'll create a custom packet named `MyPacket` using the `Packet` and `DerivedPacket` classes provided by the `mal_packet_weaver` namespace.

Let's start by defining the `MyPacket` class. This class should inherit from `DerivedPacket<MyPacket>` and implement the necessary functions.

- Note: Packets should satisfy the IsPacket concept:
  ```cpp
  template <typename T>
  concept IsPacket = requires(T packet)
  {
      // The class MUST be final
      std::is_final_v<T>;
      // It should derive from mal_packet_weaver::DerivedPacket
      std::is_base_of_v<DerivedPacket<T>, T>;
      // It should have a static constexpr UniquePacketID(or uint32_t) static_type that indicates unique packet ID.
      std::same_as<std::decay_t<decltype(T::static_type)>, UniquePacketID>;
      // It should have static constexpr float time_to_live that indicates that packets TTL within subsystems.
      std::same_as<std::decay_t<decltype(T::time_to_live)>, float>;
  };
  ```

### Declaring the Packet Type

```cpp
using mal_packet_weaver::packet::DerivedPacket;
using mal_packet_weaver::packet::UniquePacketID;
using mal_packet_weaver::packet::CreatePacketID;

// You can use underlying ID system so you won't catch yourself with intersecting IDs:
// PacketSubsystemID and PacketID are simple uint16_t's to form a UniquePacketID.
// This way you can declare PacketSubsystemIDs for your systems and you won't experience problems with it.
// If you try to register deserializer for existing packet, it will throw an exception, so you'll be notified about intersections.
constexpr PacketSubsystemID MySubsystem = 0x0000;


// Define MyPacket
class MyPacket final : public DerivedPacket<MyPacket> {
public:
    // Here you can use any number. UniquePacketID is uint32_t, CreatePacketID is a helper that combines two 16-bit unsigned integers so there's no conflicts.
    static constexpr UniquePacketID static_type = CreatePacketID(MySubsystem, 0x0010);
    static constexpr float time_to_live = 60.0f;

    // Add your packet-specific data fields here
    int packet_data;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version) {
        //
        ar &packet_data;
    }
};
```

### Using Inheritance

What if you have a lot of similar data and functions between packets and you need inheritance so there's no boilerplate code? You can use multi-inheritance to define this. Neither DerivedPacket nor Packet need to serialize any data, so we wont need to call their serialization function.

You can do something similar:

```cpp

using mal_packet_weaver::packet::DerivedPacket;
using mal_packet_weaver::packet::UniquePacketID;
using mal_packet_weaver::packet::CreatePacketID;

struct CommonData
{
    float x, y, z;
    std::string name;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version) {
        ar &x;
        ar &y;
        ar &z;
        ar &name;
    }
};

constexpr PacketSubsystemID MySubsystem = 0x0000;

class MyPacket final : public CommonData, public DerivedPacket<MyPacket> {
public:
    static constexpr UniquePacketID static_type = CreatePacketID(MySubsystem, 0x0010);
    static constexpr float time_to_live = 60.0f;

    int subpacket_specific_data_1;
    int subpacket_specific_data_2;
    int subpacket_specific_data_3;
    int subpacket_specific_data_4;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version) {
        // Add this line:
        ar &boost::serialization::base_object<CommonData>(*this);
        // And you can still serialize your variables.
        ar &subpacket_specific_data_1;
        ar &subpacket_specific_data_2;
        ar &subpacket_specific_data_3;
        ar &subpacket_specific_data_4;
    }
};
```

Or you can use it as a member:

```cpp
class MyPacket final : public DerivedPacket<MyPacket> {
public:
    static constexpr UniquePacketID static_type = CreatePacketID(MySubsystem, 0x0010);
    // Time to live defines how much the Dispatcher should wait til discarding the packet.
    static constexpr float time_to_live = 60.0f;

    int subpacket_specific_data_1;
    int subpacket_specific_data_2;
    int subpacket_specific_data_3;
    int subpacket_specific_data_4;
    // But we lose easy-to-access interface provided by CommonData.
    CommonData common_data;

private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, [[maybe_unused]] const unsigned int version) {
        // Add this line:
        ar &common_data;
        // And you can still serialize your variables.
        ar &subpacket_specific_data_1;
        ar &subpacket_specific_data_2;
        ar &subpacket_specific_data_3;
        ar &subpacket_specific_data_4;
    }
};
```

### Registering Deserializers

Don't forget to register the deserializer for your `MyPacket` class using the `PacketFactory` to ensure proper deserialization.

```cpp
    mal_packet_weaver::packet::PacketFactory::RegisterDeserializer<MyPacket>();
```

By following these steps, you've successfully created a custom packet named `MyPacket` using the provided classes and concepts. You can now use this packet to communicate specific data within your application.

## Waiting for Packets with PacketDispatcher

The `PacketDispatcher` class allows you to wait for specific packets and handle them asynchronously. This example demonstrates how to use the `PacketDispatcher` API to await and handle incoming packets.

First, let's assume you have a `PacketDispatcher` instance named `dispatcher` created and configured.

### Awaiting a Specific Packet

You can use the `await_packet` function to wait for a specific type of packet. This function will asynchronously wait until the desired packet type is received.

```cpp
#include "packet-dispatcher.hpp"

// ...

// Awaiting a specific packet type
boost::asio::awaitable<std::unique_ptr<MyPacket>> awaitMyPacket() {
    std::unique_ptr<MyPacket> packet = co_await dispatcher.await_packet<MyPacket>();
    // Process the received packet
    co_return std::move(packet);
}
```

### Awaiting a Packet with a Filter

You can also wait for a packet that satisfies a filter condition. The `await_packet` function allows you to pass a filter function that determines whether a packet should be awaited or not.

```cpp
#include "packet-dispatcher.hpp"

// ...

// Define a filter function
bool MyPacketFilter(const MyPacket& packet) {
    // Implement your filter logic here
    return packet.isValid();
}

// Awaiting a packet with a filter
boost::asio::awaitable<std::unique_ptr<MyPacket>> awaitFilteredPacket() {
    std::unique_ptr<MyPacket> packet = co_await dispatcher.await_packet<MyPacket>(MyPacketFilter);
    // Process the received packet
    co_return std::move(packet);
}

// Pass filter as a lambda
boost::asio::awaitable<std::unique_ptr<MyPacket>> awaitFilteredPacket() {
    std::unique_ptr<MyPacket> packet = co_await dispatcher.await_packet<MyPacket>(
        [](const MyPacket &packet) -> bool { return packet.some_data > 1000; }
    );
    // Process the received packet
    co_return std::move(packet);
}
```

### Registering Default Handlers

You can register default handlers to process specific packet types. These handlers will be executed when a matching packet is received. Optionally, you can provide a filter function and a delay for delayed execution. This can be used for packet awaits, so if no method wants to take the packet in time it will we passed to the packet handler.

```cpp
#include "packet-dispatcher.hpp"

// ...

// Define a packet handler function
void MyPacketHandler(std::unique_ptr<MyPacket> packet) {
    // Handle the received packet
    // ...
}

// Register a default handler for MyPacket with a filter and delay
dispatcher.register_default_handler<MyPacket>(MyPacketHandler, MyPacketFilter, 0.5f);
```

## Putting it All Together

Once you've set up your `PacketDispatcher` and registered handlers, you can start processing incoming packets. Here's an example of how you can process packets in a coroutine:

```cpp
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <iostream>
#include "mal-packet-weaver/packet-dispatcher.hpp"

int main() {
    // Create an io_context and PacketDispatcher instance
    boost::asio::io_context io_context;
    mal_packet_weaver::PacketDispatcher dispatcher(io_context);
    boost::asio::ip::tcp::socket socket(io_context);
    socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));

    // Note: session ALWAYS should be declared as shared_ptr.
    // This is done because coroutines inside the session try to create object using shared_from_this.

    // To destroy the session you should call session->Destroy() method
    auto session = std::make_shared<mal-packet-weaver::Session>(io_context, std::move(socket));

    // Start processing packets in a coroutine
    boost::asio::co_spawn(io_context, [&]() -> boost::asio::awaitable<void> {
        while (true) {
            // Wait for a specific packet
            auto packet = co_await dispatcher.await_packet<MyPacket>();
            // Process the received MyPacket

            // Respond to the server
            MyPacketResponse response;
            response.some_data = process_packet(packet);
            connection->send_packet(packet);

            // Wait for a packet with a filter
            auto filteredPacket = co_await dispatcher.await_packet<MyPacket>(
                [](const MyPacket &packet){packet.some_data > 1000;}
            );
            // Process the received filtered packet

            // ...
        }
    }, boost::asio::detached());

    // Run the io_context to start processing
    io_context.run();

    return 0;
}
```

## Thread Safety

Since the library is completely threadsafe, you can add multiple threads to the context. This can improve performance if the server is heavy-loaded:

```cpp
std::vector<std::thread> threads;
for (int i = 0; i < 8; ++i)
{
    threads.emplace_back([&io_context]() { io_context.run();});
}
io_context.run();
for (auto &thread : threads)
{
    thread.join();
}
```

This example showcases the basic usage of the `PacketDispatcher` API for awaiting and handling packets. Customize the packet types, filters, and handlers according to your application's needs.

Remember to include the necessary headers and adjust the code to match your actual project structure and requirements.

For more usage examples and detailed documentation, please refer to the [Documentation](https://malatindez.github.io/mal-packet-weaver) or [examples/](examples/) directory.

## Contributing

Contributions to the MAL Packet Weaver are welcome! If you find a bug, have a feature request, or want to contribute code, please open an issue or submit a pull request.

## License

This library is licensed under the [MIT License](LICENSE).
