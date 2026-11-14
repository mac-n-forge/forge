#include "lift/lift.h"

#include "analysis/analysis.h"
#include "diagnostic.h"
#include "lift/asm_info.h"
#include "lift/cfg.h"
#include "lift/integer.h"
#include "lift/stack.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <mutex>
#include <string_view>

namespace forge {
    namespace {
        using namespace llvm;

        InspectionError atRva(FailureCode kind, uint32_t rva, const Twine &why) {
            return InspectionError(hex(rva) + ": " + why.str(), kind);
        }

        using x86::Step;

        struct RegisterNames {
            StringLiteral wide, dword, word, lowByte, highByte;
        };

        // The first seven rows are the register-state ABI, in wire order.
        constexpr RegisterNames registerNames[] = {
            {"RAX", "EAX", "AX", "AL", "AH"},    {"RCX", "ECX", "CX", "CL", "CH"},
            {"RDX", "EDX", "DX", "DL", "DH"},    {"R8", "R8D", "R8W", "R8B", ""},
            {"R9", "R9D", "R9W", "R9B", ""},     {"R10", "R10D", "R10W", "R10B", ""},
            {"R11", "R11D", "R11W", "R11B", ""}, {"RSP", "ESP", "SP", "SPL", ""},
            {"RBP", "EBP", "BP", "BPL", ""},     {"RBX", "EBX", "BX", "BL", "BH"},
            {"RSI", "ESI", "SI", "SIL", ""},     {"RDI", "EDI", "DI", "DIL", ""},
            {"R12", "R12D", "R12W", "R12B", ""}, {"R13", "R13D", "R13W", "R13B", ""},
            {"R14", "R14D", "R14W", "R14B", ""}, {"R15", "R15D", "R15W", "R15B", ""}};
        constexpr unsigned callerSlots = 7;
        constexpr unsigned rspIndex = callerSlots;
        static_assert(std::string_view(registerNames[rspIndex].wide) == "RSP");

        // The signatureless ABI accepts a four-byte-aligned register array.
        constexpr auto registerStateAlignment = Align::Constant<4>();

        struct RegisterView {
            unsigned index, width, offset = 0;

            uint64_t writeMask() const { return width >= 32 ? UINT64_MAX : mask(); }

            uint64_t mask() const { return maskTrailingOnes<uint64_t>(width) << offset; }
        };

        using Defined = std::array<uint64_t, std::size(registerNames)>;

        struct Availability {
            Defined registers{};
            x86::FlagSet flags;

            bool intersect(const Availability &other) {
                auto before = *this;
                flags &= other.flags;
                for (size_t i = 0; i < registers.size(); ++i) {
                    registers[i] &= other.registers[i];
                }

                return registers != before.registers || flags != before.flags;
            }
        };

        struct BlockState {
            Defined writes{};
            x86::FlagEffect flags{{}, x86::FlagSet().set()};
            Availability incoming;
            BasicBlock *irBlock = nullptr;
            BasicBlock *exitBlock = nullptr;
            std::array<PHINode *, x86::FlagCount> phis{};
            x86::Flags outgoing{};
            bool queued = false;

            Availability transfer() const {
                auto result = incoming;
                result.flags = flags.apply(result.flags);
                for (size_t i = 0; i < writes.size(); ++i) {
                    result.registers[i] |= writes[i];
                }

                return result;
            }
        };

        using BlockStates = std::map<uint32_t, BlockState>;

        // Start at the lattice top. Each intersection only removes available bits.
        // Visit every reachable block once so even a block with unchanged inputs
        // propagates its own flag invalidations.
        void proveAvailability(const x86::ControlFlowGraph &graph, BlockStates &states,
                               EntryMode mode) {
            std::deque<uint32_t> pending;
            for (auto &[addr, state] : states) {
                state.incoming.registers.fill(UINT64_MAX);
                state.incoming.flags.set();
                state.queued = true;
                pending.push_back(addr);
            }

            auto &entry = states.begin()->second.incoming;
            entry.flags.reset();
            entry.registers.fill(0);
            entry.registers[rspIndex] = UINT64_MAX;

            if (mode == EntryMode::RegisterState) {
                std::fill_n(entry.registers.begin(), callerSlots, UINT64_MAX);
            } else {
                entry.registers[1] = entry.registers[2] = UINT64_MAX;
            }

            while (!pending.empty()) {
                const auto addr = pending.front();
                pending.pop_front();
                auto &source = states.at(addr);
                source.queued = false;
                const auto out = source.transfer();

                for (auto target : graph.at(addr).successors) {
                    auto &dest = states.at(target);
                    if (dest.incoming.intersect(out) && !dest.queued) {
                        dest.queued = true;
                        pending.push_back(target);
                    }
                }
            }
        }

        std::optional<uint8_t> shiftCount(const Step &s, x86::Form form) {
            if (form == x86::Form::ShiftOne) {
                return 1U;
            }

            if (form == x86::Form::ShiftImmediate) {
                return static_cast<uint8_t>(
                    s.inst.getOperand(s.inst.getNumOperands() - 1).getImm());
            }

            return {};
        }

        class Translator {
          public:
            Translator(llvm::Module &module, uint32_t rva, EntryMode mode,
                       const MCRegisterInfo &regs)
                : ir(module.getContext()), semantics(ir), stack(ir), regs(regs), mode(mode) {
                auto *type = FunctionType::get(ir.getVoidTy(), ir.getPtrTy(), false);
                impl = Function::Create(type, Function::InternalLinkage,
                                        "forge_lifted_" + utohexstr(rva, true), module);
                impl->getArg(0)->setName("state");
                appendToUsed(module, {impl});
                auto *stateType = ArrayType::get(ir.getInt64Ty(), callerSlots);

                if (mode == EntryMode::WindowsX64I64Pair) {
                    auto *nativeType = FunctionType::get(ir.getInt64Ty(),
                                                         {ir.getInt64Ty(), ir.getInt64Ty()}, false);
                    auto *native = Function::Create(nativeType, Function::ExternalLinkage,
                                                    "forge_lifted", module);
                    ir.SetInsertPoint(BasicBlock::Create(module.getContext(), "entry", native));
                    auto *state = ir.CreateAlloca(stateType);
                    // Backing bits for partial writes must be concrete. Read eligibility is
                    // proved separately, so these zeros are never exposed as incoming values.
                    ir.CreateStore(ConstantAggregateZero::get(stateType), state);
                    ir.CreateStore(native->getArg(0), slot(state, 1));
                    ir.CreateStore(native->getArg(1), slot(state, 2));
                    ir.CreateCall(impl, state);
                    ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), slot(state, 0)));
                }
            }

            void translate(const x86::ControlFlowGraph &graph);

          private:
            IRBuilder<> ir;
            x86::IntegerSemantics semantics;
            x86::GuestStack stack;
            const MCRegisterInfo &regs;
            EntryMode mode;
            Function *impl;
            Value *localRegisters = nullptr;
            bool accessesMemory = false;
            bool writesRsp = false;
            Defined defined{};

            Value *slot(Value *state, unsigned index) {
                if (index >= callerSlots) {
                    return ir.CreateInBoundsGEP(ir.getInt64Ty(), localRegisters,
                                                ir.getInt32(index - callerSlots));
                }

                return ir.CreateInBoundsGEP(ir.getInt64Ty(), state, ir.getInt32(index));
            }

            RegisterView reg(const Step &s, const MCOperand &operand, unsigned width) const;
            Value *read(const Step &s, RegisterView view);
            Value *value(const Step &s, const MCOperand &operand, unsigned width);
            void write(RegisterView view, Value *v);
            Value *require(const Step &s, x86::Flag flag) const;
            Value *condition(const Step &s);
            void integer(const Step &s, const x86::IntegerInstruction &instruction);
            void lower(const Step &s);
            Value *effectiveAddress(const Step &s, unsigned first, bool memory);
            RegisterView destination(const Step &s,
                                     const x86::IntegerInstruction &instruction) const;
            std::optional<RegisterView> resultRegister(const Step &s) const;
            void summarize(const Step &s, BlockState &state);
            void emitBlock(const x86::GuestBlock &block, const BlockStates &states);
        };

        RegisterView Translator::reg(const Step &s, const MCOperand &op, unsigned width) const {
            if (!op.isReg() || !op.getReg()) {
                s.reject(FailureCode::UnsupportedRegister, "expected a general-purpose register");
            }

            auto name = StringRef(regs.getName(op.getReg()));

            for (unsigned index = 0; index < std::size(registerNames); ++index) {
                const auto &names = registerNames[index];

                if ((width == 64 && names.wide == name) || (width == 32 && names.dword == name) ||
                    (width == 16 && names.word == name) || (width == 8 && names.lowByte == name)) {
                    return {index, width};
                }

                if (width == 8 && names.highByte == name) {
                    return {index, width, 8};
                }
            }

            s.reject(FailureCode::UnsupportedRegister, "unsupported register " + name);
        }

        Value *Translator::read(const Step &s, RegisterView view) {
            if ((defined[view.index] & view.mask()) != view.mask()) {
                s.reject(FailureCode::UndefinedRegister,
                         "read of undefined incoming " + registerNames[view.index].wide);
            }

            Value *v = ir.CreateAlignedLoad(ir.getInt64Ty(), slot(impl->getArg(0), view.index),
                                            registerStateAlignment);
            if (view.offset) {
                v = ir.CreateLShr(v, view.offset);
            }

            return ir.CreateTruncOrBitCast(v, ir.getIntNTy(view.width));
        }

        Value *Translator::value(const Step &s, const MCOperand &op, unsigned width) {
            if (op.isImm()) {
                return ConstantInt::getSigned(ir.getIntNTy(width), op.getImm());
            }

            return read(s, reg(s, op, width));
        }

        void Translator::write(RegisterView view, Value *v) {
            auto *ptr = slot(impl->getArg(0), view.index);
            auto *result = ir.CreateZExtOrBitCast(v, ir.getInt64Ty());

            if (view.width < 32) {
                auto *parent = ir.CreateAlignedLoad(ir.getInt64Ty(), ptr, registerStateAlignment);
                result = ir.CreateOr(ir.CreateAnd(parent, ~view.mask()),
                                     ir.CreateShl(result, view.offset));
            }

            defined[view.index] |= view.writeMask();
            ir.CreateAlignedStore(result, ptr, registerStateAlignment);
        }

        Value *Translator::require(const Step &s, x86::Flag flag) const {
            if (!semantics.flags[flag]) {
                s.reject(FailureCode::UndefinedFlag,
                         "unsupported use of undefined condition flags: " + x86::flagNames[flag]);
            }

            return semantics.flags[flag];
        }

        Value *Translator::condition(const Step &s) {
            auto code = s.inst.getOperand(s.inst.getNumOperands() - 1).getImm();

            if (code < 0 || code > 15) {
                s.reject(FailureCode::UnsupportedInstruction, "unsupported condition code");
            }

            return semantics.condition(static_cast<unsigned>(code),
                                       [&](x86::Flag f) { return require(s, f); });
        }

        Value *Translator::effectiveAddress(const Step &s, unsigned first, bool memory) {
            const auto &inst = s.inst;
            const auto &base = inst.getOperand(first);
            const auto scale = inst.getOperand(first + 1).getImm();
            const auto &index = inst.getOperand(first + 2);
            const auto displacement = inst.getOperand(first + 3).getImm();
            const auto segment = inst.getOperand(first + 4).getReg();
            const bool hasIndex =
                index.getReg() && StringRef(regs.getName(index.getReg())) != "RIZ";

            if (segment || (scale != 1 && scale != 2 && scale != 4 && scale != 8)) {
                s.reject(FailureCode::UnsupportedInstruction,
                         "unsupported segment or address scale");
            }

            if (memory && !base.getReg() && !hasIndex) {
                s.reject(FailureCode::UnsupportedInstruction, "absolute memory operand");
            }

            Value *address = ir.getInt64(static_cast<uint64_t>(displacement));

            if (base.getReg()) {
                address = ir.CreateAdd(address, read(s, reg(s, base, 64)));
            }

            if (hasIndex) {
                auto *term = read(s, reg(s, index, 64));
                address = ir.CreateAdd(
                    address, ir.CreateMul(term, ir.getInt64(static_cast<uint64_t>(scale))));
            }

            return address;
        }

        RegisterView Translator::destination(const Step &s,
                                             const x86::IntegerInstruction &instruction) const {
            if (instruction.form == x86::Form::Accumulator) {
                return {0, instruction.width};
            }

            return reg(s, s.inst.getOperand(0), instruction.width);
        }

        std::optional<RegisterView> Translator::resultRegister(const Step &s) const {
            if (s.opcode == "LAHF") {
                return RegisterView{0, 8, 8};
            }

            unsigned width = 0;
            if (s.opcode == "LEA64r" || s.opcode == "CMOV64rr") {
                width = 64;
            } else if (s.opcode == "LEA64_32r" || s.opcode == "CMOV32rr") {
                width = 32;
            } else if (s.opcode == "CMOV16rr") {
                width = 16;
            } else if (s.opcode == "SETCCr") {
                width = 8;
            } else {
                return {};
            }

            return reg(s, s.inst.getOperand(0), width);
        }

        void Translator::summarize(const Step &s, BlockState &state) {
            RegisterView dest{};
            if (auto instruction = x86::integerInstruction(s.opcode)) {
                if (instruction->form == x86::Form::Store) {
                    accessesMemory = true;
                    return;
                }

                accessesMemory |= instruction->form == x86::Form::Load;
                auto effect = x86::flagEffect(instruction->op, instruction->width,
                                              shiftCount(s, instruction->form));
                state.flags.generated = effect.apply(state.flags.generated);
                state.flags.carried &= effect.carried;

                if (instruction->op == x86::Op::Cmp || instruction->op == x86::Op::Test) {
                    return;
                }

                dest = destination(s, *instruction);
            } else if (auto result = resultRegister(s)) {
                dest = *result;
            } else {
                return;
            }

            state.writes[dest.index] |= dest.writeMask();
            writesRsp |= dest.index == rspIndex;
        }

        void Translator::integer(const Step &s, const x86::IntegerInstruction &instruction) {
            using x86::Form;
            using x86::Op;
            auto [op, form, width, sourceWidth] = instruction;
            const auto &i = s.inst;
            const auto &last = i.getOperand(i.getNumOperands() - 1);

            if (form == Form::Store) {
                auto *address = effectiveAddress(s, 0, true);
                stack.store(address, value(s, last, width));
                return;
            }

            auto dest = destination(s, instruction);

            if (op == Op::Mov || op == Op::Movsx || op == Op::Movzx) {
                auto *source = form == Form::Load
                                   ? stack.load(effectiveAddress(s, 1, true), sourceWidth)
                                   : value(s, last, sourceWidth);
                write(dest, ir.CreateIntCast(source, ir.getIntNTy(width), op == Op::Movsx));

                return;
            }

            if (form == Form::ShiftCL || form == Form::ShiftOne || form == Form::ShiftImmediate) {
                auto fixed = shiftCount(s, form);
                auto *count = fixed ? ir.getInt8(*fixed) : read(s, {1, 8});
                write(dest, semantics.shift(op, read(s, dest), count));

                return;
            }

            // Equal operands cancel even if the guest register has no incoming value.
            // SBB still subtracts CF, and CMP only updates flags.
            bool cancel = (op == Op::Xor || op == Op::Sub || op == Op::Cmp || op == Op::Sbb) &&
                          form == Form::Pair && i.getOperand(0).getReg() == last.getReg();
            Value *lhs = cancel ? ir.getIntN(width, 0) : read(s, dest);
            Value *rhs = nullptr;

            if (form != Form::Reg) {
                rhs = cancel ? lhs : value(s, last, width);
            }

            if (op == Op::Adc || op == Op::Sbb) {
                require(s, x86::CF);
            }

            auto *result = semantics.arithmetic(op, lhs, rhs);
            if (op != Op::Cmp && op != Op::Test) {
                write(dest, result);
            }
        }

        void Translator::lower(const Step &s) {
            if (auto instruction = x86::integerInstruction(s.opcode)) {
                integer(s, *instruction);
                return;
            }

            auto result = resultRegister(s);
            if (!result) {
                s.reject(FailureCode::UnsupportedInstruction,
                         "unsupported instruction or operand form");
            }

            const auto dest = *result;
            if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
                write(dest, ir.CreateTruncOrBitCast(effectiveAddress(s, 1, false),
                                                    ir.getIntNTy(dest.width)));
            } else if (s.opcode == "SETCCr") {
                write(dest, ir.CreateZExt(condition(s), ir.getInt8Ty()));
            } else if (s.opcode == "CMOV16rr" || s.opcode == "CMOV32rr" || s.opcode == "CMOV64rr") {
                auto *old = read(s, dest);
                auto *src = value(s, s.inst.getOperand(2), dest.width);

                write(dest, ir.CreateSelect(condition(s), src, old));
            } else if (s.opcode == "LAHF") {
                Value *byte = ir.getInt8(2);

                for (auto [flag, bit] : {std::pair{x86::SF, 7U},
                                         {x86::ZF, 6U},
                                         {x86::AF, 4U},
                                         {x86::PF, 2U},
                                         {x86::CF, 0U}}) {
                    byte = ir.CreateOr(
                        byte, ir.CreateShl(ir.CreateZExt(require(s, flag), ir.getInt8Ty()), bit));
                }

                write(dest, byte);
            } else {
                llvm_unreachable("unhandled result-register instruction");
            }
        }

        void Translator::emitBlock(const x86::GuestBlock &block, const BlockStates &states) {
            const auto &last = block.steps.back();
            auto body = ArrayRef(block.steps);
            if (block.exit != x86::Flow::Fallthrough && block.exit != x86::Flow::FallOff) {
                body = body.drop_back();
            }

            for (const auto &s : body) {
                lower(s);
            }

            switch (block.exit) {
            case x86::Flow::Return:
                if (mode == EntryMode::WindowsX64I64Pair && defined[0] != UINT64_MAX) {
                    last.reject(FailureCode::UndefinedRegister, "return with undefined RAX");
                }

                if (writesRsp) {
                    stack.checkReturn(read(last, {rspIndex, 64}));
                }

                ir.CreateRetVoid();
                break;
            case x86::Flow::Conditional:
                ir.CreateCondBr(condition(last), states.at(block.successors[0]).irBlock,
                                states.at(block.successors[1]).irBlock);
                break;
            case x86::Flow::Fallthrough:
            case x86::Flow::Jump:
                ir.CreateBr(states.at(block.successors.front()).irBlock);
                break;
            case x86::Flow::FallOff:
                last.reject(FailureCode::UnsupportedControlFlow,
                            "fallthrough outside function to " + hex(last.next), last.next);
            }
        }

        void connectFlags(const x86::ControlFlowGraph &graph, const BlockStates &states) {
            for (const auto &[addr, block] : graph) {
                const auto &source = states.at(addr);
                for (auto dest : block.successors) {
                    const auto &phis = states.at(dest).phis;
                    for (unsigned f = 0; f < x86::FlagCount; ++f) {
                        if (phis[f]) {
                            assert(source.outgoing[f] &&
                                   "availability disagrees with flag lowering");
                            phis[f]->addIncoming(source.outgoing[f], source.exitBlock);
                        }
                    }
                }
            }
        }

        void Translator::translate(const x86::ControlFlowGraph &graph) {
            BlockStates states;
            auto *entry = BasicBlock::Create(ir.getContext(), "entry", impl);
            for (const auto &[addr, block] : graph) {
                auto &state = states[addr];
                state.irBlock =
                    BasicBlock::Create(ir.getContext(), "rva_" + utohexstr(addr, true), impl);
                try {
                    for (const auto &s : block.steps) {
                        summarize(s, state);
                    }
                } catch (InspectionError &failure) {
                    failure.context.blockRva = addr;
                    throw;
                }
            }

            proveAvailability(graph, states, mode);
            ir.SetInsertPoint(entry);
            auto *locals = ArrayType::get(ir.getInt64Ty(), std::size(registerNames) - callerSlots);
            localRegisters = ir.CreateAlloca(locals, nullptr, "local.registers");
            ir.CreateStore(ConstantAggregateZero::get(locals), localRegisters);
            ir.CreateAlignedStore(ir.getInt64(x86::GuestStack::entryRsp),
                                  slot(impl->getArg(0), rspIndex), registerStateAlignment);

            if (accessesMemory) {
                stack.allocate();
            }

            ir.CreateBr(states.begin()->second.irBlock);
            for (const auto &[addr, block] : graph) {
                auto &state = states.at(addr);
                ir.SetInsertPoint(state.irBlock);
                defined = state.incoming.registers;
                semantics.flags = {};
                for (unsigned f = 0; f < x86::FlagCount; ++f) {
                    if (state.incoming.flags[f]) {
                        state.phis[f] = ir.CreatePHI(ir.getInt1Ty(), 0, x86::flagNames[f]);
                        semantics.flags[f] = state.phis[f];
                    }
                }

                try {
                    emitBlock(block, states);
                } catch (InspectionError &failure) {
                    failure.context.blockRva = addr;
                    throw;
                }

                state.exitBlock = ir.GetInsertBlock();
                state.outgoing = semantics.flags;
            }

            connectFlags(graph, states);
        }

        struct ValidatedEntry {
            LiftRequest request;
            // The analyzed image owns both the section and its bytes through generation.
            MappedRange code;
        };

        unsigned relocationWidth(unsigned type) {
            switch (type) {
            case COFF::IMAGE_REL_BASED_ABSOLUTE:
                return 0;
            case COFF::IMAGE_REL_BASED_HIGH:
            case COFF::IMAGE_REL_BASED_LOW:
            case COFF::IMAGE_REL_BASED_HIGHADJ:
                return 2;
            case COFF::IMAGE_REL_BASED_HIGHLOW:
                return 4;
            default:
                return 8;
            }
        }

        ValidatedEntry validateEntry(const AnalyzedImage &analysis, LiftRequest request,
                                     FailureContext &location) {
            const auto rva = request.startRva;
            const auto &module = analysis.module();

            if (module.dll) {
                throw atRva(FailureCode::DllLift, rva, "DLL lifting is unsupported");
            }

            const auto &functions = analysis.functions();
            auto it = llvm::lower_bound(functions, rva, [](const auto &function, uint32_t address) {
                return function.record.begin < address;
            });

            const auto first = it;
            // An invalid empty record can share its start with a valid, disjoint record.
            while (it != functions.end() && it->record.begin == rva &&
                   (it->defect || it->overlapGroup)) {
                ++it;
            }

            if (it == functions.end() || it->record.begin != rva) {
                auto kind = FailureCode::InvalidEntry;

                if (it - first == 1 && !first->overlapGroup &&
                    first->defect == RecordDefect::UnmappedCode) {
                    kind = FailureCode::UnmappedCode;
                    location.endRva = first->record.end;
                }

                throw atRva(kind, rva,
                            "expected an exact, valid, unambiguous discovered function start");
            }

            const auto end = it->record.end;
            location.endRva = end;

            if (const auto version = it->unsupportedUnwindVersion) {
                throw atRva(FailureCode::UnsupportedUnwind, rva,
                            "unsupported unwind version " + Twine(*version));
            }

            if (it->chainedFragment) {
                throw atRva(FailureCode::ChainedEntry, rva,
                            "chained unwind fragment has no independent function entry");
            }

            auto code = analysis.image().mapRva(rva, end - rva);

            if (!code) {
                throw atRva(FailureCode::UnmappedCode, rva,
                            "function bytes outside file-backed sections");
            }

            location.fileOffset = code->fileOffset;

            for (const auto &block : module.relocations) {
                for (const auto &rel : block.entries) {
                    const auto width = relocationWidth(rel.type);

                    if (width && rel.rva < end && uint64_t(rel.rva) + width > rva) {
                        throw atRva(FailureCode::RelocationOverlap, rva,
                                    "function bytes overlap base relocation at " + hex(rel.rva));
                    }
                }
            }

            return {request, *code};
        }

        std::unique_ptr<llvm::Module> generateAmd64IR(const ValidatedEntry &entry,
                                                      LLVMContext &context) {
            const uint32_t rva = entry.request.startRva;
            // LLVM registry writes must finish before another lift looks up its decoder.
            static std::once_flag registerAmd64;
            std::call_once(registerAmd64, [] {
                LLVMInitializeX86TargetInfo();
                LLVMInitializeX86TargetMC();
                LLVMInitializeX86Disassembler();
            });

            const Triple guestTriple("x86_64-pc-windows-msvc");
            std::string error;
            const auto *target = TargetRegistry::lookupTarget(guestTriple, error);

            if (!target) {
                throw atRva(FailureCode::BackendSetup, rva, error);
            }

            std::unique_ptr<MCRegisterInfo> regs(target->createMCRegInfo(guestTriple));
            std::unique_ptr<MCInstrInfo> instructions(target->createMCInstrInfo());
            std::unique_ptr<MCSubtargetInfo> sub(
                target->createMCSubtargetInfo(guestTriple, "generic", ""));

            if (!regs || !instructions || !sub) {
                throw atRva(FailureCode::BackendSetup, rva, "AMD64 decoder metadata unavailable");
            }

            const MCTargetOptions options;
            auto assembly = x86::createAsmInfo(*target, *regs, guestTriple, options);

            if (!assembly) {
                throw atRva(FailureCode::BackendSetup, rva,
                            "AMD64 assembly information unavailable");
            }

            MCContext mc(guestTriple, *assembly, *regs, *sub);
            std::unique_ptr<MCDisassembler> dis(target->createMCDisassembler(*sub, mc));

            if (!dis) {
                throw atRva(FailureCode::BackendSetup, rva, "AMD64 disassembler unavailable");
            }

            const auto graph = x86::discoverCFG(entry.code.bytes, rva, *dis, *instructions);
            auto module = std::make_unique<llvm::Module>("forge_" + utohexstr(rva, true), context);
            const Triple outputTriple("arm64-apple-macosx11.0.0");
            module->setTargetTriple(outputTriple);
            module->setDataLayout(outputTriple.computeDataLayout());
            Translator(*module, rva, entry.request.mode, *regs).translate(graph);
            return module;
        }
    } // namespace

    void verifyLiftedIR(const llvm::Module &module, const fs::path &input, uint32_t entryRva) {
        std::string message;
        llvm::raw_string_ostream reason(message);

        if (llvm::verifyModule(module, &reason)) {
            auto failure =
                atRva(FailureCode::VerificationFailed, entryRva, "LLVM verifier: " + message);
            failure.context.input = input;
            failure.context.entryRva = entryRva;
            throw failure;
        }
    }

    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context) {
        FailureContext location;
        location.input = analysis.module().path;
        location.entryRva = request.startRva;
        FailureCode internal = FailureCode::EntryInternal;

        try {
            const auto entry = validateEntry(analysis, request, location);
            internal = FailureCode::LiftingInternal;
            auto module = generateAmd64IR(entry, context);
            internal = FailureCode::VerificationInternal;
            verifyLiftedIR(*module, location.input, request.startRva);
            return module;
        } catch (InspectionError &failure) {
            if (location.fileOffset && failure.context.instructionRva) {
                *location.fileOffset += *failure.context.instructionRva - request.startRva;
            }

            failure.context.input = std::move(location.input);
            failure.context.entryRva = location.entryRva;
            failure.context.endRva = location.endRva;
            failure.context.fileOffset = location.fileOffset;
            throw;
        } catch (const std::exception &error) {
            InspectionError failure(error.what(), internal);
            failure.context = std::move(location);
            throw failure;
        }
    }
} // namespace forge
