#include "champions/archive.hpp"

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace {
using Buffer = std::vector<std::uint8_t>;
namespace fs = std::filesystem;
int checks = 0;

void check(bool condition, const std::string& label) {
    ++checks;
    if (!condition) {
        throw std::runtime_error("failed: " + label);
    }
}

champions::Bytes view(const Buffer& data) { return {data.data(), data.size()}; }

void put32(Buffer& data, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        data.at(offset + i) = static_cast<std::uint8_t>((value >> (8 * i)) & 255);
    }
}

void putText(Buffer& data, std::size_t offset, const std::string& text) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        data.at(offset + i) = static_cast<std::uint8_t>(text[i]);
    }
}

Buffer lump() {
    // Two authored entries: a three-byte payload and an empty payload at EOF.
    Buffer data(44, 0);
    put32(data, 0, 2);
    put32(data, 4, 28); put32(data, 8, 41); put32(data, 12, 3);
    put32(data, 16, 34); put32(data, 20, 44); put32(data, 24, 0);
    putText(data, 28, "alpha"); putText(data, 34, "empty");
    data[41] = 0x11; data[42] = 0x22; data[43] = 0x33;
    return data;
}

Buffer gob(const Buffer& child) {
    Buffer data(80 + child.size(), 0);
    putText(data, 0, "example.LmP");
    put32(data, 32, 80); put32(data, 36, static_cast<std::uint32_t>(child.size()));
    for (std::size_t i = 0; i < child.size(); ++i) {
        data[80 + i] = child[i];
    }
    return data;
}

void rejects(const std::string& label, const std::function<void()>& call,
             const std::string& detail) {
    try {
        call();
    } catch (const champions::FormatError& error) {
        check(std::string(error.what()).find(detail) != std::string::npos,
              label + " reports the failing field");
        return;
    }
    check(false, label + " must reject input");
}

void runTests() {
    auto lmp = lump();
    const auto entries = champions::readLmp(view(lmp));
    check(entries.size() == 2, "LMP record count");
    check(entries[0].name == "alpha" && entries[0].offset == 41 && entries[0].size == 3,
          "LMP metadata");
    check(entries[1].name == "empty" && entries[1].offset == 44 && entries[1].size == 0,
          "zero-length entry at EOF");
    check(champions::payload(view(lmp), entries[0]).data[1] == 0x22, "bounded payload view");
    check(champions::readLmp(view(Buffer(4, 0))).empty(), "empty LMP");
    check(champions::readGob(view(Buffer(40, 0))).empty(), "empty GOB");

    auto archive = gob(lmp);
    const auto outer = champions::readGob(view(archive));
    check(outer.size() == 1 && outer[0].name == "example.LmP" && outer[0].offset == 80,
          "GOB metadata");
    const auto inner = champions::readLmp(champions::payload(view(archive), outer[0]));
    check(inner[0].offset + outer[0].offset == 121 && inner[0].name == "alpha",
          "nested metadata and absolute offset");

    auto fullName = archive;
    putText(fullName, 0, std::string(32, 'A'));
    check(champions::readGob(view(fullName))[0].name == std::string(32, 'A'),
          "GOB names bounded to 32 bytes even without a zero");

    for (std::size_t size : {std::size_t(0), std::size_t(1), std::size_t(3)}) {
        rejects("truncated LMP header", [&] { champions::readLmp(view(Buffer(size, 0))); }, "32-bit");
    }
    auto countOverflow = lmp;
    put32(countOverflow, 0, 0xffffffffU);
    rejects("excessive LMP count", [&] { champions::readLmp(view(countOverflow)); }, "count");
    auto tableTruncated = lmp;
    tableTruncated.resize(27);
    rejects("truncated record table", [&] { champions::readLmp(view(tableTruncated)); }, "count");

    auto badName = lmp;
    put32(badName, 4, static_cast<std::uint32_t>(badName.size()));
    rejects("name exactly at EOF", [&] { champions::readLmp(view(badName)); }, "name offset");
    put32(badName, 4, 0xffffffffU);
    rejects("name offset wraparound", [&] { champions::readLmp(view(badName)); }, "name offset");
    badName = lmp;
    put32(badName, 4, 41);
    rejects("unterminated name", [&] { champions::readLmp(view(badName)); }, "terminating");

    auto badData = lmp;
    put32(badData, 8, 45);
    rejects("payload offset outside file", [&] { champions::readLmp(view(badData)); }, "payload");
    badData = lmp;
    put32(badData, 12, 4);
    rejects("payload crosses EOF", [&] { champions::readLmp(view(badData)); }, "payload");
    put32(badData, 8, 0xfffffff0U); put32(badData, 12, 0x40);
    rejects("payload offset plus length wraps 32 bits", [&] { champions::readLmp(view(badData)); }, "payload");

    rejects("truncated GOB", [&] { champions::readGob(view(Buffer(39, 0))); }, "record");
    auto noTerminator = archive;
    noTerminator.resize(40);
    put32(noTerminator, 32, 0); put32(noTerminator, 36, 0);
    rejects("missing GOB terminator", [&] { champions::readGob(view(noTerminator)); }, "terminator");
    auto badGobData = archive;
    put32(badGobData, 32, 0xffffffffU);
    rejects("GOB payload bounds", [&] { champions::readGob(view(badGobData)); }, "payload");

    auto nestedTruncated = gob(Buffer(3, 0));
    // Extra bytes outside the declared child cannot make its header valid.
    nestedTruncated.push_back(0);
    auto truncatedEntries = champions::readGob(view(nestedTruncated));
    rejects("nested length isolation", [&] {
        champions::readLmp(champions::payload(view(nestedTruncated), truncatedEntries[0]));
    }, "32-bit");
    rejects("direct payload view bounds", [&] {
        champions::payload(view(lmp), champions::Entry{"bad", 43, 2});
    }, "payload");

    Buffer endian(260, 0);
    put32(endian, 0, 1); put32(endian, 4, 16);
    put32(endian, 8, 258); put32(endian, 12, 2);
    putText(endian, 16, "endian");
    check(champions::readLmp(view(endian))[0].offset == 258,
          "little-endian offset spans multiple bytes");
    check(champions::hasExtension("C:\\Game Data\\Archive.GoB", ".gob"),
          "Windows separators, spaces and mixed-case extension");
    check(!champions::hasExtension("archive.GOB.bak", ".gob"), "extension must be last");
    check(champions::escapeTsv(std::string("a\tb\n\\") + char(0xff)) == "a\\tb\\n\\\\\\xff",
          "TSV control, slash and non-ASCII byte escaping");

    // Every truncated version is still bounded, whether valid or invalid.
    for (std::size_t length = 0; length < archive.size(); ++length) {
        const champions::Bytes prefix{archive.data(), length};
        try {
            for (const auto& entry : champions::readGob(prefix)) {
                champions::readLmp(champions::payload(prefix, entry));
            }
        } catch (const champions::FormatError&) {
            continue;
        }
    }
    check(true, "all prefixes handled without an out-of-range access");
}

void write(const fs::path& path, const Buffer& data) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file) throw std::runtime_error("cannot write synthetic fixture");
}

int run(const std::vector<fs::path>& args) {
    try {
        if (args.size() == 2 && args[0] == "--write-fixtures") {
            fs::create_directories(args[1]);
            write(args[1] / "nested.GOB", gob(lump()));
            write(args[1] / "empty.LMP", Buffer(4, 0));
            write(args[1] / "invalid.LMP", Buffer(3, 0));
            write(args[1] / fs::u8path("Ch\xc3\xa4mpions \xe6\xb5\x8b\xe8\xaf\x95.LMP"), lump());
            return 0;
        }
        if (!args.empty()) throw std::runtime_error("unexpected test arguments");
        runTests();
        std::cout << checks << " parser checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    std::vector<fs::path> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    return run(args);
}
#else
int main(int argc, char** argv) {
    std::vector<fs::path> args;
    for (int i = 1; i < argc; ++i) args.push_back(fs::u8path(argv[i]));
    return run(args);
}
#endif
