// Observed contract at 0x00207310: write the low 16 bits of the second
// argument into the halfword at byte offset 0x6a of the supplied storage.
// Callers 0x002072a8 and 0x002033ac supply signed halfwords. Field meaning and
// original type remain unknown; storage must permit an aligned 16-bit write.
extern "C" void champions_rebuild_00207310(unsigned short* storage, int value) noexcept {
    storage[0x35] = static_cast<unsigned short>(value);
}
