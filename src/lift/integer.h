#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"

#include <array>
#include <bitset>
#include <optional>

namespace forge::x86 {
    enum class Op {
        Mov,
        Movzx,
        Movsx,
        Add,
        Adc,
        Sub,
        Sbb,
        Cmp,
        Inc,
        Dec,
        Neg,
        Imul,
        And,
        Or,
        Xor,
        Not,
        Test,
        Shl,
        Shr,
        Sar
    };

    enum class Form {
        Reg,
        Pair,
        Immediate,
        Accumulator,
        Extend,
        Load,
        Store,
        MemoryImmediate,
        ShiftOne,
        ShiftImmediate,
        ShiftCL
    };

    struct IntegerInstruction {
        Op op;
        Form form;
        unsigned width;
        unsigned sourceWidth;
    };

    std::optional<IntegerInstruction> integerInstruction(llvm::StringRef opcode);

    enum Flag : unsigned { CF, PF, AF, ZF, SF, OF, FlagCount };

    inline constexpr std::array<llvm::StringLiteral, FlagCount> flagNames{"CF", "PF", "AF",
                                                                          "ZF", "SF", "OF"};
    // A null entry means the flag lacks a definition valid for every possible execution.
    using Flags = std::array<llvm::Value *, FlagCount>;

    using FlagSet = std::bitset<FlagCount>;

    // Availability after an operation is generated | (incoming & carried).
    // A variable-count shift can carry availability while changing the bit value.
    struct FlagEffect {
        FlagSet generated;
        FlagSet carried;

        FlagSet apply(FlagSet incoming) const { return generated | (incoming & carried); }
    };

    FlagEffect flagEffect(Op op, unsigned width, std::optional<unsigned> count = {});

    class IntegerSemantics {
      public:
        explicit IntegerSemantics(llvm::IRBuilder<> &builder) : ir(builder) {}

        Flags flags{};
        llvm::Value *arithmetic(Op op, llvm::Value *lhs, llvm::Value *rhs);
        llvm::Value *shift(Op op, llvm::Value *operand, llvm::Value *count);
        llvm::Value *condition(unsigned code, llvm::function_ref<llvm::Value *(Flag)> require);

      private:
        llvm::IRBuilder<> &ir;
        void resultFlags(llvm::Value *result);
        llvm::Value *addSub(bool subtract, llvm::Value *lhs, llvm::Value *rhs, llvm::Value *carry);
    };
} // namespace forge::x86
