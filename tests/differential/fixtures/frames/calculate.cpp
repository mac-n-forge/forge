#include "arithmetic/decimal_pairs.h"

extern "C" __attribute__((dllexport, noipa)) int64_t calculate(int64_t a, int64_t b) {
    volatile int64_t values[3] = {a, b, a + b};
    return values[0] * values[1] + values[2];
}

int main(int argc, char **argv) {
    // The common decimal parser also accepts pairs whose product would overflow.
    for (int i = 1; i < argc; ++i) {
        int64_t operand;
        if (!parse_operand(argv[i], &operand) || operand < -1000000000 || operand > 1000000000) {
            return 2;
        }
    }

    return run_decimal_pairs(argc, argv, calculate);
}
