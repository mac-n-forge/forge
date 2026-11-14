#include "lift/integer.h"

#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/Module.h"

#include <stdexcept>

using namespace forge::x86;
using namespace llvm;

namespace {
    Constant *evaluate(Value *value) {
        auto *inst = dyn_cast_or_null<Instruction>(value);
        if (inst) {
            // IRBuilder leaves intrinsics (including ctpop) as calls even for constants.
            // Fold the actual emitted IR before reading the architectural result.
            SmallVector<Constant *> inputs;
            for (Value *operand : inst->operands()) {
                inputs.push_back(evaluate(operand));
            }
            return ConstantFoldInstOperands(inst, inputs, inst->getModule()->getDataLayout());
        }
        return dyn_cast_or_null<Constant>(value);
    }

    void expect(Value *value, uint64_t expected, StringRef scenario) {
        const auto *constant = dyn_cast_or_null<ConstantInt>(evaluate(value));
        if (!constant || constant->getZExtValue() != expected) {
            throw std::runtime_error(scenario.str());
        }
    }

    // Flag bits use their architectural positions, so the literals can be checked
    // directly against an ADD/SUB truth table or a saved arithmetic flags word.
    void expectFlags(const Flags &flags, unsigned values, unsigned available, StringRef scenario) {
        constexpr std::array<unsigned, FlagCount> bits{1, 4, 16, 64, 128, 2048};
        for (unsigned i = 0; i < FlagCount; ++i) {
            auto label = (scenario + " " + flagNames[i]).str();
            if (available & bits[i]) {
                expect(flags[i], static_cast<unsigned>((values & bits[i]) != 0), label);
            } else if (flags[i]) {
                throw std::runtime_error(label + " unexpectedly defined");
            }
        }
    }

    void checkFlagAvailability(StringRef opcode, IRBuilder<> &ir, Value *count = nullptr,
                               std::optional<unsigned> fixed = {}) {
        const auto instruction = integerInstruction(opcode);
        if (!instruction) {
            throw std::runtime_error("unrecognized test opcode " + opcode.str());
        }

        const auto effect = flagEffect(instruction->op, instruction->width, fixed);
        auto *operand = ir.getIntN(instruction->width, 7);
        IntegerSemantics semantics(ir);

        for (unsigned mask = 0; mask < (1U << FlagCount); ++mask) {
            const FlagSet incoming(mask);
            // The translator requires carry before calling arithmetic for ADC or SBB.
            if ((instruction->op == Op::Adc || instruction->op == Op::Sbb) && !incoming[CF]) {
                continue;
            }

            for (unsigned f = 0; f < FlagCount; ++f) {
                semantics.flags[f] = incoming[f] ? ir.getTrue() : nullptr;
            }

            if (count) {
                semantics.shift(instruction->op, operand, count);
            } else {
                semantics.arithmetic(instruction->op, operand, operand);
            }

            FlagSet actual;
            for (unsigned f = 0; f < FlagCount; ++f) {
                actual[f] = semantics.flags[f] != nullptr;
            }

            const auto expected = effect.apply(incoming);
            if (actual != expected) {
                throw std::runtime_error(opcode.str() + " with incoming flags " +
                                         incoming.to_string() + ": expected " +
                                         expected.to_string() + ", emitted " + actual.to_string());
            }
        }
    }

    void checkShiftEffects(StringRef operation, unsigned width, IRBuilder<> &ir, Value *cl) {
        const auto prefix = operation.str() + std::to_string(width);
        checkFlagAvailability(prefix + "rCL", ir, cl);
        checkFlagAvailability(prefix + "r1", ir, ir.getInt8(1), 1);

        for (unsigned count : {0U, 1U, width - 1, width, width + 1, 32U, 64U}) {
            checkFlagAvailability(prefix + "ri", ir, ir.getInt8(static_cast<uint8_t>(count)),
                                  count);
        }
    }

    void checkMemoryForms() {
        struct Case {
            StringLiteral opcode;
            Form form;
            unsigned width, sourceWidth;
        };

        constexpr Case cases[] = {
            {"MOV8mr", Form::Store, 8, 8},       {"MOV16mi", Form::Store, 16, 16},
            {"MOV32rm", Form::Load, 32, 32},     {"MOV64mi32", Form::Store, 64, 64},
            {"MOVZX16rm8", Form::Load, 16, 8},   {"MOVSX64rm16", Form::Load, 64, 16},
            {"MOVSX64rm32", Form::Load, 64, 32}, {"MOVSX32rm32", Form::Load, 32, 32}};

        for (const auto &sample : cases) {
            const auto inst = integerInstruction(sample.opcode);

            if (!inst || inst->form != sample.form || inst->width != sample.width ||
                inst->sourceWidth != sample.sourceWidth) {
                throw std::runtime_error("incorrect memory form " + sample.opcode.str());
            }

            const auto effect = flagEffect(inst->op, inst->width);

            if (effect.generated.any() || !effect.carried.all()) {
                throw std::runtime_error("move affected condition flags " + sample.opcode.str());
            }
        }

        for (const auto &[opcode, form] : {std::pair{"CMP32rm", Form::Load},
                                           {"CMP64mi8", Form::MemoryImmediate},
                                           {"ADD32mi8", Form::MemoryImmediate}}) {
            auto instruction = integerInstruction(opcode);

            if (!instruction || instruction->form != form ||
                !flagEffect(instruction->op, instruction->width).generated.all()) {
                throw std::runtime_error(std::string("incorrect arithmetic memory form ") + opcode);
            }
        }

        for (StringRef opcode :
             {"ADD64rm", "MOVZX64rm32", "MOVSX16rm16", "MOVSX16rm32", "MOV64mi", "MOV8ao64"}) {
            if (integerInstruction(opcode)) {
                throw std::runtime_error("accepted unsupported form " + opcode.str());
            }
        }
    }

    void checkEffects() {
        LLVMContext context;
        Module module("availability", context);
        auto *type = FunctionType::get(Type::getVoidTy(context), Type::getInt8Ty(context), false);
        auto *fn = Function::Create(type, Function::InternalLinkage, "test", module);
        IRBuilder<> ir(BasicBlock::Create(context, "entry", fn));

        for (auto opcode : {"ADD8rr", "ADC8ri", "SUB8ri", "SBB8rr", "CMP8i8", "INC8r", "DEC8r",
                            "NEG8r", "NOT8r", "AND8rr", "OR8rr", "XOR8rr", "TEST8rr", "IMUL16rr"}) {
            checkFlagAvailability(opcode, ir);
        }

        for (StringRef operation : {"SHL", "SHR", "SAR"}) {
            for (unsigned width : {8U, 16U, 32U, 64U}) {
                checkShiftEffects(operation, width, ir, fn->getArg(0));
            }
        }
    }

    void check() {
        LLVMContext context;
        Module module("integer-tests", context);
        auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(context), false),
                                    Function::InternalLinkage, "test", module);
        IRBuilder<> ir(BasicBlock::Create(context, "entry", fn));
        IntegerSemantics semantics(ir);
        constexpr unsigned all = 0x8d5;
        constexpr unsigned status = 0xc4;

        auto arithmetic = [&](Op op, unsigned lhs, unsigned rhs) {
            return semantics.arithmetic(op, ir.getInt8(static_cast<uint8_t>(lhs)),
                                        ir.getInt8(static_cast<uint8_t>(rhs)));
        };
        expect(arithmetic(Op::Add, 0xff, 1), 0, "unsigned wrap");
        expectFlags(semantics.flags, 0x55, all, "ff + 1");
        expect(arithmetic(Op::Inc, 0x7f, 0), 0x80, "signed increment");
        expectFlags(semantics.flags, 0x891, all, "INC preserves carry");
        expect(arithmetic(Op::Adc, 0x80, 0xff), 0x80, "carry into negative operands");
        expectFlags(semantics.flags, 0x91, all, "80 + ff + 1");
        expect(arithmetic(Op::Dec, 0x80, 0), 0x7f, "signed decrement");
        expectFlags(semantics.flags, 0x811, all, "DEC preserves carry");
        expect(arithmetic(Op::Not, 0x0f, 0), 0xf0, "bitwise inverse");
        expectFlags(semantics.flags, 0x811, all, "NOT preserves flags");
        expect(arithmetic(Op::Sbb, 0, 0x7f), 0x80, "borrow in");
        expectFlags(semantics.flags, 0x91, all, "00 - 7f - 1");
        expect(arithmetic(Op::Neg, 0x80, 0), 0x80, "negate minimum");
        expectFlags(semantics.flags, 0x881, all, "NEG minimum");
        arithmetic(Op::Cmp, 0x80, 0x7f);
        auto require = [&](Flag f) { return semantics.flags[f]; };
        expect(semantics.condition(12, require), 1, "signed less");
        expect(semantics.condition(2, require), 0, "unsigned below");
        arithmetic(Op::Test, 0xf0, 0x0f);
        expectFlags(semantics.flags, 0x44, all & ~16U, "TEST disjoint");
        expect(semantics.condition(4, require), 1, "TEST zero");
        arithmetic(Op::Add, 0x7f, 1);
        expect(semantics.condition(0, require), 1, "ADD overflow");

        arithmetic(Op::Sub, 0, 1);
        expect(arithmetic(Op::Adc, 0x7f, 0), 0x80, "carry alone causes signed overflow");
        expectFlags(semantics.flags, 0x890, all, "7f + 0 + 1");
        arithmetic(Op::Sub, 0, 1);
        expect(arithmetic(Op::Sbb, 0x80, 0), 0x7f, "borrow alone causes signed overflow");
        expectFlags(semantics.flags, 0x810, all, "80 - 0 - 1");
        expect(semantics.arithmetic(Op::Add, ir.getInt64(INT64_MAX), ir.getInt64(1)),
               uint64_t{1} << 63, "64-bit signed boundary");
        expectFlags(semantics.flags, 0x894, all, "64-bit signed overflow without carry");
        expect(semantics.arithmetic(Op::Add, ir.getInt32(UINT32_MAX), ir.getInt32(1)), 0,
               "32-bit wrap");
        expectFlags(semantics.flags, 0x55, all, "32-bit carry without signed overflow");
        arithmetic(Op::Add, 0x7f, 1);
        auto shift = [&](Op op, unsigned n) {
            return semantics.shift(op, ir.getInt8(0x81), ir.getInt8(static_cast<uint8_t>(n)));
        };
        expect(shift(Op::Shl, 32), 0x81, "masked-zero shift");
        expectFlags(semantics.flags, 0x890, all, "masked-zero preserves flags");
        expect(shift(Op::Shl, 1), 2, "left shift");
        expectFlags(semantics.flags, 0x801, all & ~16U, "SHL one");
        expect(shift(Op::Shr, 8), 0, "narrow logical shift");
        expectFlags(semantics.flags, 0x44, status, "SHR at width");
        expect(shift(Op::Sar, 31), 0xff, "saturating arithmetic shift");
        expectFlags(semantics.flags, 0x85, status | 1U, "SAR beyond width");
        expect(shift(Op::Sar, 1), 0xc0, "arithmetic shift");
        expectFlags(semantics.flags, 0x85, all & ~16U, "SAR one");
    }
} // namespace

int main() {
    try {
        check();
        checkEffects();
        checkMemoryForms();
    } catch (const std::exception &error) {
        errs() << "integer semantics: " << error.what() << '\n';
        return 1;
    }
}
