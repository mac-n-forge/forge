#include "lift/integer.h"

#include "llvm/ADT/StringSwitch.h"

namespace forge::x86 {
    using namespace llvm;

    namespace {
        std::optional<IntegerInstruction> moveInstruction(Op op, unsigned width, StringRef suffix) {
            // MOVSXD without REX.W can copy a doubleword into a 32-bit destination.
            if (op == Op::Movsx && width == 32 && suffix == "rm32") {
                return IntegerInstruction{op, Form::Load, 32, 32};
            }

            if (op != Op::Mov) {
                Form form;

                if (suffix.consume_front("rm")) {
                    form = Form::Load;
                } else if (suffix.consume_front("rr")) {
                    form = Form::Extend;
                } else {
                    return std::nullopt;
                }

                unsigned sourceWidth = 0;

                if (suffix.getAsInteger(10, sourceWidth) || sourceWidth >= width ||
                    !(sourceWidth == 8 || sourceWidth == 16 ||
                      (op == Op::Movsx && sourceWidth == 32))) {
                    return std::nullopt;
                }

                return IntegerInstruction{op, form, width, sourceWidth};
            }

            Form form;

            if (suffix == "rm") {
                form = Form::Load;
            } else if (suffix == "mr" || (width < 64 && suffix == "mi") ||
                       (width == 64 && suffix == "mi32")) {
                form = Form::Store;
            } else if (suffix == "rr" || suffix == "rr_REV") {
                form = Form::Pair;
            } else if (suffix == "ri" || suffix == "ri_alt" || suffix == "ri32" ||
                       suffix == "ri8") {
                form = Form::Immediate;
            } else {
                return std::nullopt;
            }

            return IntegerInstruction{op, form, width, width};
        }
    } // namespace

    std::optional<IntegerInstruction> integerInstruction(StringRef opcode) {
        auto name = opcode.take_while([](char c) { return c >= 'A' && c <= 'Z'; });
        auto operation = StringSwitch<std::optional<Op>>(name)
                             .Case("MOV", Op::Mov)
                             .Case("MOVZX", Op::Movzx)
                             .Case("MOVSX", Op::Movsx)
                             .Case("ADD", Op::Add)
                             .Case("ADC", Op::Adc)
                             .Case("SUB", Op::Sub)
                             .Case("SBB", Op::Sbb)
                             .Case("CMP", Op::Cmp)
                             .Case("INC", Op::Inc)
                             .Case("DEC", Op::Dec)
                             .Case("NEG", Op::Neg)
                             .Case("IMUL", Op::Imul)
                             .Case("AND", Op::And)
                             .Case("OR", Op::Or)
                             .Case("XOR", Op::Xor)
                             .Case("NOT", Op::Not)
                             .Case("TEST", Op::Test)
                             .Case("SHL", Op::Shl)
                             .Case("SHR", Op::Shr)
                             .Case("SAR", Op::Sar)
                             .Default(std::nullopt);

        if (!operation) {
            return std::nullopt;
        }

        StringRef suffix = opcode.drop_front(name.size());
        unsigned width = 0;

        if (suffix.consumeInteger(10, width) ||
            (width != 8 && width != 16 && width != 32 && width != 64)) {

            return std::nullopt;
        }

        const auto op = *operation;

        if (op == Op::Mov || op == Op::Movzx || op == Op::Movsx) {
            return moveInstruction(op, width, suffix);
        }

        Form form;

        if (opcode == "CMP32rm") {
            form = Form::Load;
        } else if (opcode == "CMP64mi8" || opcode == "ADD32mi8") {
            form = Form::MemoryImmediate;
        } else if (op == Op::Shl || op == Op::Shr || op == Op::Sar) {
            if (suffix == "r1") {
                form = Form::ShiftOne;
            } else if (suffix == "ri") {
                form = Form::ShiftImmediate;
            } else if (suffix == "rCL") {
                form = Form::ShiftCL;
            } else {
                return std::nullopt;
            }
        } else if (op == Op::Not || op == Op::Neg || op == Op::Inc || op == Op::Dec) {
            if (suffix != "r") {
                return std::nullopt;
            }

            form = Form::Reg;
        } else if (suffix == "rr" || suffix == "rr_REV") {
            form = Form::Pair;
        } else if (op != Op::Imul && (suffix == "ri" || suffix == "ri8" || suffix == "ri32")) {
            form = Form::Immediate;
        } else if (op != Op::Imul && (suffix == "i8" || suffix == "i16" || suffix == "i32")) {
            form = Form::Accumulator;
        } else {
            return std::nullopt;
        }

        return IntegerInstruction{op, form, width, width};
    }

    FlagEffect flagEffect(Op op, unsigned width, std::optional<unsigned> count) {
        FlagSet all;
        all.set();
        const FlagSet carry(1U << CF);
        const FlagSet overflow(1U << OF);
        const FlagSet logical = all & ~FlagSet(1U << AF);
        switch (op) {
        case Op::Mov:
        case Op::Movsx:
        case Op::Movzx:
        case Op::Not:
            return {{}, all};
        case Op::Inc:
        case Op::Dec:
            return {all & ~carry, carry};
        case Op::Imul:
            return {carry | overflow, {}};
        case Op::And:
        case Op::Or:
        case Op::Test:
        case Op::Xor:
            return {logical, {}};
        case Op::Shl:
        case Op::Shr:
        case Op::Sar: {
            if (count) {
                *count &= width == 64 ? 63U : 31U;
            }

            if (count == 0) {
                return {{}, all};
            }

            auto available = logical;
            available[OF] = count == 1;
            available[CF] = op == Op::Sar || width >= 32 || (count && *count < width);
            return count ? FlagEffect{available, {}} : FlagEffect{{}, available};
        }
        default:
            return {all, {}};
        }
    }

    void IntegerSemantics::resultFlags(Value *result) {
        flags[ZF] = ir.CreateIsNull(result);
        flags[SF] = ir.CreateIsNeg(result);
        auto *byte = ir.CreateTruncOrBitCast(result, ir.getInt8Ty());
        auto *population = ir.CreateUnaryIntrinsic(Intrinsic::ctpop, byte);
        flags[PF] = ir.CreateNot(ir.CreateTrunc(population, ir.getInt1Ty()));
    }

    Value *IntegerSemantics::addSub(bool subtract, Value *lhs, Value *rhs, Value *carry) {
        auto *first = subtract ? ir.CreateSub(lhs, rhs) : ir.CreateAdd(lhs, rhs);
        Value *result = first;
        auto *cf = subtract ? ir.CreateICmpULT(lhs, rhs) : ir.CreateICmpULT(first, lhs);

        if (carry) {
            auto *bit = ir.CreateZExt(carry, lhs->getType());
            result = subtract ? ir.CreateSub(first, bit) : ir.CreateAdd(first, bit);
            auto *secondCarry =
                subtract ? ir.CreateICmpULT(first, bit) : ir.CreateICmpULT(result, first);
            cf = ir.CreateOr(cf, secondCarry);
        }

        flags[CF] = cf;
        auto *different = ir.CreateXor(lhs, rhs);
        auto *changed = ir.CreateXor(lhs, result);
        flags[OF] =
            ir.CreateIsNeg(ir.CreateAnd(subtract ? different : ir.CreateNot(different), changed));
        flags[AF] = ir.CreateIsNotNull(ir.CreateAnd(ir.CreateXor(different, result), 0x10));
        resultFlags(result);

        return result;
    }

    Value *IntegerSemantics::arithmetic(Op op, Value *lhs, Value *rhs) {
        auto availability = flagEffect(op, lhs->getType()->getIntegerBitWidth());
        for (unsigned f = 0; f < FlagCount; ++f) {
            if (!availability.generated[f] && !availability.carried[f]) {
                flags[f] = nullptr;
            }
        }

        switch (op) {
        case Op::Add:
        case Op::Adc:
        case Op::Sub:
        case Op::Sbb:
        case Op::Cmp:
            return addSub(op != Op::Add && op != Op::Adc, lhs, rhs,
                          op == Op::Adc || op == Op::Sbb ? flags[CF] : nullptr);
        case Op::Inc:
        case Op::Dec: {
            auto *carry = flags[CF];
            auto *result = addSub(op == Op::Dec, lhs, ConstantInt::get(lhs->getType(), 1), nullptr);
            flags[CF] = carry;
            return result;
        }
        case Op::Neg:
            return addSub(true, ConstantInt::get(lhs->getType(), 0), lhs, nullptr);
        case Op::Not:
            return ir.CreateNot(lhs);
        case Op::Imul: {
            auto *product = ir.CreateBinaryIntrinsic(Intrinsic::smul_with_overflow, lhs, rhs);
            flags[CF] = flags[OF] = ir.CreateExtractValue(product, 1);
            return ir.CreateExtractValue(product, 0);
        }
        case Op::And:
        case Op::Test:
        case Op::Or:
        case Op::Xor: {
            auto *result = op == Op::Xor  ? ir.CreateXor(lhs, rhs)
                           : op == Op::Or ? ir.CreateOr(lhs, rhs)
                                          : ir.CreateAnd(lhs, rhs);
            resultFlags(result);
            flags[CF] = flags[OF] = ir.getFalse();

            return result;
        }
        default:
            llvm_unreachable("operation is handled outside arithmetic");
        }
    }

    Value *IntegerSemantics::shift(Op op, Value *operand, Value *count) {
        unsigned width = operand->getType()->getIntegerBitWidth();
        auto *n = ir.CreateAnd(ir.CreateZExt(count, ir.getInt64Ty()), width == 64 ? 63 : 31);
        auto *fixed = dyn_cast<ConstantInt>(n);

        if (fixed && fixed->isZero()) {
            return operand;
        }

        Flags prior = flags;
        auto *wide = ir.CreateIntCast(operand, ir.getInt64Ty(), op == Op::Sar);
        auto shifted = [&](Value *distance) {
            if (op == Op::Shl) {
                return ir.CreateShl(wide, distance);
            }

            if (op == Op::Shr) {
                return ir.CreateLShr(wide, distance);
            }

            return ir.CreateAShr(wide, distance);
        };

        auto *result = ir.CreateTruncOrBitCast(shifted(n), operand->getType());
        resultFlags(result);
        flags[AF] = nullptr;

        // Model the final one-bit step. Both distances are always legal i64 shifts,
        // including zero and counts greater than the narrow guest operand width.
        auto *beforeLast = shifted(ir.CreateAnd(ir.CreateSub(n, ir.getInt64(1)), 63));
        auto *carry = ir.CreateTrunc(
            op == Op::Shl ? ir.CreateLShr(beforeLast, width - 1) : beforeLast, ir.getInt1Ty());
        auto effect = flagEffect(
            op, width, fixed ? std::optional<unsigned>(fixed->getZExtValue()) : std::nullopt);
        flags[CF] = (effect.generated[CF] || effect.carried[CF]) ? carry : nullptr;
        flags[OF] = nullptr;

        if (effect.generated[OF]) {
            flags[OF] = op == Op::Sar   ? ir.getFalse()
                        : op == Op::Shr ? ir.CreateIsNeg(operand)
                                        : ir.CreateXor(flags[SF], carry);
        }

        if (!fixed) {
            auto *zero = ir.CreateIsNull(n);

            for (unsigned f = 0; f < FlagCount; ++f) {
                flags[f] =
                    prior[f] && flags[f] ? ir.CreateSelect(zero, prior[f], flags[f]) : nullptr;
            }
        }

        return result;
    }

    Value *IntegerSemantics::condition(unsigned code, function_ref<Value *(Flag)> require) {
        Value *bit = nullptr;

        switch (code >> 1) {
        case 0:
            bit = require(OF);
            break;
        case 1:
            bit = require(CF);
            break;
        case 2:
            bit = require(ZF);
            break;
        case 3:
            bit = ir.CreateOr(require(CF), require(ZF));
            break;
        case 4:
            bit = require(SF);
            break;
        case 5:
            bit = require(PF);
            break;
        case 6:
            bit = ir.CreateXor(require(SF), require(OF));
            break;
        case 7:
            bit = ir.CreateOr(ir.CreateXor(require(SF), require(OF)), require(ZF));
            break;
        default:
            llvm_unreachable("invalid condition nibble");
        }

        return code & 1U ? ir.CreateNot(bit) : bit;
    }
} // namespace forge::x86
