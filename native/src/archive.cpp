#include "champions/archive.hpp"

#include <limits>
#include <utility>

namespace champions {
namespace {

void requireRange(Bytes bytes, std::size_t offset, std::size_t size,
                  const std::string& field) {
    // Subtraction avoids overflow in offset + size, on either 32- or 64-bit hosts.
    if (offset > bytes.size || size > bytes.size - offset) {
        throw FormatError(field + " extends outside the archive");
    }
}

std::uint32_t little32(Bytes bytes, std::size_t offset) {
    requireRange(bytes, offset, 4, "32-bit field");
    return static_cast<std::uint32_t>(bytes.data[offset]) |
           (static_cast<std::uint32_t>(bytes.data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes.data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes.data[offset + 3]) << 24);
}

std::string fixedName(Bytes bytes, std::size_t offset, std::size_t width) {
    requireRange(bytes, offset, width, "GOB name");
    std::size_t length = 0;
    while (length < width && bytes.data[offset + length] != 0) {
        ++length;
    }
    // A full-width fixed field is valid; do not scan past its 32-byte boundary.
    return std::string(reinterpret_cast<const char*>(bytes.data + offset), length);
}

std::string terminatedName(Bytes bytes, std::size_t offset) {
    requireRange(bytes, offset, 1, "LMP name offset");
    std::size_t end = offset;
    while (end < bytes.size && bytes.data[end] != 0) {
        ++end;
    }
    if (end == bytes.size) {
        throw FormatError("LMP name is missing its terminating zero byte");
    }
    return std::string(reinterpret_cast<const char*>(bytes.data + offset), end - offset);
}

char asciiLower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

} // namespace

std::vector<Entry> readGob(Bytes bytes) {
    std::vector<Entry> entries;
    std::size_t offset = 0;
    for (;;) {
        requireRange(bytes, offset, 40, "GOB table record or empty terminator");
        if (bytes.data[offset] == 0) {
            return entries;
        }
        Entry entry{fixedName(bytes, offset, 32), little32(bytes, offset + 32),
                    little32(bytes, offset + 36)};
        requireRange(bytes, entry.offset, entry.size, "GOB entry payload");
        entries.push_back(std::move(entry));
        offset += 40; // A complete record above proves this addition is in range.
    }
}

std::vector<Entry> readLmp(Bytes bytes) {
    const auto count = little32(bytes, 0);
    if (count > (bytes.size - 4) / 12) {
        throw FormatError("LMP entry count exceeds the available record table");
    }
    std::vector<Entry> entries;
    entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t record = 4 + static_cast<std::size_t>(i) * 12;
        const auto nameOffset = little32(bytes, record);
        Entry entry{terminatedName(bytes, nameOffset), little32(bytes, record + 4),
                    little32(bytes, record + 8)};
        requireRange(bytes, entry.offset, entry.size, "LMP entry payload");
        entries.push_back(std::move(entry));
    }
    return entries;
}

Bytes payload(Bytes bytes, const Entry& entry) {
    requireRange(bytes, entry.offset, entry.size, "Entry payload");
    // Avoid pointer arithmetic on a null pointer for an empty byte range.
    return Bytes{entry.offset == 0 ? bytes.data : bytes.data + entry.offset, entry.size};
}

bool hasExtension(const std::string& name, const std::string& extension) {
    if (extension.size() > name.size()) {
        return false;
    }
    const auto offset = name.size() - extension.size();
    for (std::size_t i = 0; i < extension.size(); ++i) {
        if (asciiLower(name[offset + i]) != asciiLower(extension[i])) {
            return false;
        }
    }
    return true;
}

std::string escapeTsv(const std::string& text) {
    constexpr char hex[] = "0123456789abcdef";
    std::string escaped;
    for (unsigned char c : text) {
        switch (c) {
        case '\\': escaped += "\\\\"; break;
        case '\t': escaped += "\\t"; break;
        case '\r': escaped += "\\r"; break;
        case '\n': escaped += "\\n"; break;
        default:
            if (c < 32 || c >= 127) {
                escaped += "\\x";
                escaped += hex[c >> 4];
                escaped += hex[c & 15];
            } else {
                escaped += static_cast<char>(c);
            }
        }
    }
    return escaped;
}

} // namespace champions
