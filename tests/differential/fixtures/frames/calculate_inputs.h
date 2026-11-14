#pragma once

#include "../arithmetic/operand.h"

// Preflight the whole command line so every product and sum fits before any output.
static inline bool validCalculateInputs(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        int64_t operand;
        if (!parse_operand(argv[i], &operand) || operand < -1000000000 || operand > 1000000000) {
            return false;
        }
    }
    return true;
}
