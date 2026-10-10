// Observed contract at 0x00208b94: replace the 32-bit word at byte offset
// 0x400 in the supplied storage with the second argument. Callers include
// 0x00142f24 (loaded word) and 0x00209450 (constant 1). The field's meaning
// and original surrounding type are unknown; the destination must be aligned.
extern "C" void champions_rebuild_00208b94(unsigned int* storage, unsigned int value) noexcept {
    storage[0x100] = value;
}
