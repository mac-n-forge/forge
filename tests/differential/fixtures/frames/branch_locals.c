#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa)) int64_t branch_locals(int64_t a, int64_t b) {
    volatile uint8_t low = (uint8_t)a;
    volatile int16_t delta = (int16_t)b;
    volatile int32_t sum = (int32_t)low + delta;
    if (a < 0) {
        if (sum < 0) {
            return sum;
        }

        return (int64_t)sum + low;
    }

    return (int64_t)sum - delta;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, branch_locals); }
