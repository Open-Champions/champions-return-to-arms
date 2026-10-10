#include "champions/archive.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;

void usage(std::ostream& out) {
    out << "Champions native data inspector\n"
        << "Usage: champions-data list <archive.GOB|archive.LMP> [more archives...]\n"
        << "Lists metadata only; GOB entries ending in .LMP are also inspected.\n"
        << "Offsets are decimal bytes from the containing input file.\n"
        << "Names and paths use escaped TSV bytes; no files are extracted.\n";
}

std::vector<std::uint8_t> readFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("cannot open input file");
    }
    const auto end = file.tellg();
    if (end < 0) {
        throw std::runtime_error("cannot determine input size");
    }
    const auto length = static_cast<std::uintmax_t>(end);
    if (length > std::numeric_limits<std::size_t>::max() ||
        length > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::runtime_error("input file is too large for this build");
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(length));
    file.seekg(0);
    if (!data.empty() &&
        !file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("cannot read the complete input file");
    }
    return data;
}

void row(std::ostream& out, const char* kind, const std::string& parent,
         const champions::Entry& entry, std::uint64_t base) {
    out << kind << '\t' << champions::escapeTsv(parent) << '\t'
        << champions::escapeTsv(entry.name) << '\t'
        << base + entry.offset << '\t' << entry.size << '\n';
}

std::string inspect(const fs::path& path) {
    const auto extension = path.extension().u8string();
    const bool gob = champions::hasExtension(extension, ".gob");
    if (!gob && !champions::hasExtension(extension, ".lmp")) {
        throw std::runtime_error("expected a .GOB or .LMP file (extension is case-insensitive)");
    }
    const auto data = readFile(path);
    const champions::Bytes bytes{data.data(), data.size()};
    std::ostringstream out;
    out << "file\t" << champions::escapeTsv(path.u8string()) << '\n'
        << "kind\tparent\tname\toffset\tsize\n";
    if (gob) {
        for (const auto& entry : champions::readGob(bytes)) {
            row(out, "gob-entry", "", entry, 0);
            if (champions::hasExtension(entry.name, ".lmp")) {
                try {
                    for (const auto& child : champions::readLmp(champions::payload(bytes, entry))) {
                        row(out, "lmp-entry", entry.name, child, entry.offset);
                    }
                } catch (const champions::FormatError& error) {
                    throw champions::FormatError("nested LMP '" +
                        champions::escapeTsv(entry.name) + "': " + error.what());
                }
            }
        }
    } else {
        for (const auto& entry : champions::readLmp(bytes)) {
            row(out, "lmp-entry", "", entry, 0);
        }
    }
    // Emit only after the entire file and any nested lumps passed validation.
    return out.str();
}

int run(const std::vector<fs::path>& args) {
    if (args.size() == 1 && (args[0] == "--help" || args[0] == "-h")) {
        usage(std::cout);
        return 0;
    }
    if (args.size() < 2 || args[0] != "list") {
        usage(std::cerr);
        return 2;
    }
    bool failed = false;
    for (std::size_t i = 1; i < args.size(); ++i) {
        try {
            std::cout << inspect(args[i]);
        } catch (const std::exception& error) {
            failed = true;
            std::cerr << "error\t" << champions::escapeTsv(args[i].u8string())
                      << '\t' << error.what() << '\n';
        }
    }
    return failed ? 1 : 0;
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    std::vector<std::filesystem::path> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return run(args);
}
#else
int main(int argc, char** argv) {
    std::vector<std::filesystem::path> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(std::filesystem::u8path(argv[i]));
    }
    return run(args);
}
#endif
