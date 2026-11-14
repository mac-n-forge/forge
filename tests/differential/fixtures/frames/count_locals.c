#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa)) int64_t count_locals(int64_t a, int64_t b) {
    volatile int64_t total = b;
    unsigned limit = (unsigned)a & 7U;
    for (unsigned i = 0; i < limit; ++i) {
        total += i;
    }

    return total;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, count_locals); }
