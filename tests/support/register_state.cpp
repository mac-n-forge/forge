#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" void probe(void *slots);

int main() {
    for (unsigned invocation = 0; invocation < 2; ++invocation) {
        // Eight-byte alignment of the allocation makes the first slot exactly 4 mod 8.
        alignas(8) std::array<std::uint32_t, 16> storage{};
        storage.front() = 0x01234567;
        storage.back() = 0x89abcdef;

        for (unsigned slot = 0; slot < 7; ++slot) {
            const std::uint64_t seed =
                0xabcdef0123456000ULL + invocation * 0x1000ULL + slot * 0x101ULL;
            std::memcpy(&storage[1 + 2 * slot], &seed, sizeof(seed));
        }

        probe(&storage[1]);

        if (std::fwrite(storage.data(), sizeof(storage), 1, stdout) != 1) {
            return 1;
        }
    }

    return std::fflush(stdout) == 0 ? 0 : 1;
}
