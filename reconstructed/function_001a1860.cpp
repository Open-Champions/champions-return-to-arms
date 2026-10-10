// Observed contract at 0x001a1860: clear the first 32-bit word of the supplied
// storage. No calls, other memory accesses, or return-value assignment occur.
// This reconstructs the complete leaf; it does not claim the surrounding type.
extern "C" void champions_rebuild_001a1860(unsigned int* first_word) noexcept {
    *first_word = 0U;
}
