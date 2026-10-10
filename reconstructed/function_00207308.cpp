// Observed contract at 0x00207308: write the low 16 bits of the second
// argument into the halfword at byte offset 0x68 of the supplied storage.
// Callers include 0x0020729c and 0x00203394. Field meaning and original type
// remain unknown; storage must permit an aligned 16-bit write at this offset.
extern "C" void champions_rebuild_00207308(unsigned short* storage, int value) noexcept {
    storage[0x34] = static_cast<unsigned short>(value);
}
