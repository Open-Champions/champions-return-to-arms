// Observed contract at 0x00155108: write the low byte of the second argument
// to offset 0x23a in the storage supplied as the first argument. Both observed
// direct callers pass 1 and ignore a return value. The original object type,
// field meaning and declared parameter width are unknown; callers must provide
// writable storage containing this byte.
extern "C" void champions_rebuild_00155108(unsigned char* storage,
                                           unsigned int value) noexcept {
    storage[0x23a] = static_cast<unsigned char>(value);
}
