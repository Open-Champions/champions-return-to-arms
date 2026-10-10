#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace champions {

struct Bytes {
    const std::uint8_t* data;
    std::size_t size;
};

struct Entry {
    std::string name;
    std::uint32_t offset;
    std::uint32_t size;
};

class FormatError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Entries always reference the supplied byte range; parsing never extracts files.
std::vector<Entry> readGob(Bytes bytes);
std::vector<Entry> readLmp(Bytes bytes);
Bytes payload(Bytes bytes, const Entry& entry);
bool hasExtension(const std::string& name, const std::string& extension);
std::string escapeTsv(const std::string& text);

} // namespace champions
