// Observed contract at 0x001707b0: clear the byte at offset 4 in the storage
// supplied as the first argument. Caller 0x00116a0c passes object+0x114 and
// reuses that pointer afterward. The original type and field meaning are not
// asserted; the caller must supply writable storage containing this byte.
extern "C" void champions_rebuild_001707b0(unsigned char* storage) noexcept {
    storage[4] = 0;
}
