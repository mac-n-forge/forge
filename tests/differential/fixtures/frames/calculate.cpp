#include "arithmetic/decimal_pairs.h"
#include "calculate_inputs.h"

extern "C" __attribute__((dllexport, noipa)) int64_t calculate(int64_t a, int64_t b) {
    volatile int64_t values[3] = {a, b, a + b};
    return values[0] * values[1] + values[2];
}

int main(int argc, char **argv) {
    if (!validCalculateInputs(argc, argv)) {
        return 2;
    }

    return run_decimal_pairs(argc, argv, calculate);
}
