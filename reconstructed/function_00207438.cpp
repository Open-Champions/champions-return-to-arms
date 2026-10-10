// Observed contract at 0x00207438: replace the byte at offset 0x16c in the
// supplied storage with the low eight bits of the second argument. The caller
// at 0x0027e8b0 supplies 5. The field's meaning and surrounding type are unknown.
extern "C" void champions_rebuild_00207438(void* storage, unsigned int value) noexcept {
    static_cast<unsigned char*>(storage)[0x16c] = static_cast<unsigned char>(value);
}
