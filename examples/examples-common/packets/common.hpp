#include "packet-crypto.hpp"
#include "packet-network.hpp"

std::string bytes_to_hex_str(mal_toolkit::ByteView const byte_view)
{
    std::string rv;
    for (int i = 0; i < byte_view.size(); i++)
    {
        const uint8_t val = static_cast<uint8_t>(byte_view[i]);
        const static std::string hex_values = "0123456789abcdef";
        rv += hex_values[val >> 4];
        rv += hex_values[val & 0xF];
    }
    return rv;
}

mal_packet_weaver::crypto::Key read_key(std::filesystem::path const &path)
{
    mal_packet_weaver::crypto::Key key;
    std::ifstream key_file(path);
    // count amount of bytes in file
    key_file.seekg(0, std::ios::end);
    key.resize(key_file.tellg());
    key_file.seekg(0, std::ios::beg);
    key_file.read(reinterpret_cast<char *>(key.data()), key.size());
    key_file.close();
    return key;
}