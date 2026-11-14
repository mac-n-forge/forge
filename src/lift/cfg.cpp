#include "lift/cfg.h"
#include "lift/integer.h"
#include "pe/image.h"

#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"

#include <set>

namespace forge::x86 {
    using namespace llvm;

    void Step::reject(FailureCode kind, const Twine &reason, std::optional<int64_t> target) const {
        auto encoded = toHex(bytes, true);
        InspectionError failure(hex(rva) + ": " + (opcode + " [" + encoded + "]: " + reason).str(),
                                kind);
        failure.context.instructionRva = rva;
        failure.context.opcode = opcode.str();
        failure.context.bytes = std::move(encoded);
        failure.context.branchTarget = target;
        throw failure;
    }

    namespace {
        bool legacyPrefix(uint8_t b) {
            switch (b) {
            case 0xf0:
            case 0xf2:
            case 0xf3:
            case 0x2e:
            case 0x36:
            case 0x3e:
            case 0x26:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
                return true;
            default:
                return false;
            }
        }

        void checkPrefix(const Step &s) {
            auto encoding = arrayRefFromStringRef(s.bytes);
            if (encoding.front() == 0x66) {
                auto instruction = x86::integerInstruction(s.opcode);

                if ((!instruction || instruction->width != 16) && s.opcode != "CMOV16rr" &&
                    s.opcode != "NOOPW") {
                    s.reject(FailureCode::UnsupportedPrefix, "unsupported instruction prefix");
                }

                encoding = encoding.drop_front();
            }

            if (!encoding.empty() && (encoding.front() & 0xf0U) == 0x40) {
                encoding = encoding.drop_front();
            }

            if (encoding.empty() || legacyPrefix(encoding.front()) ||
                (encoding.front() & 0xf0U) == 0x40) {
                s.reject(FailureCode::UnsupportedPrefix, "unsupported instruction prefix");
            }
        }

        Step decodeStep(StringRef tail, uint32_t rva, const MCDisassembler &dis,
                        const MCInstrInfo &info) {
            MCInst inst;
            uint64_t size = 0;
            if (dis.getInstruction(inst, size, arrayRefFromStringRef(tail), rva, nulls()) !=
                    MCDisassembler::Success ||
                !size || size > tail.size()) {
                auto encoded = toHex(tail.take_front(15), true);
                InspectionError failure(hex(rva) + ": invalid or truncated x86 instruction [" +
                                            encoded + "]",
                                        FailureCode::InvalidInstruction);
                failure.context.instructionRva = rva;
                failure.context.bytes = std::move(encoded);
                throw failure;
            }

            auto opcode = info.getName(inst.getOpcode());
            return {rva, static_cast<uint32_t>(rva + size), std::move(inst), opcode,
                    tail.take_front(size)};
        }

        Flow control(const Step &s, const MCInstrInfo &info) {
            if (s.opcode == "RET64") {
                return Flow::Return;
            }

            if (s.opcode == "JMP_1" || s.opcode == "JMP_4") {
                return Flow::Jump;
            }

            if (s.opcode == "JCC_1" || s.opcode == "JCC_4") {
                return Flow::Conditional;
            }

            const auto &desc = info.get(s.inst.getOpcode());
            if (desc.isCall() || desc.isBranch() || desc.isReturn()) {
                s.reject(FailureCode::UnsupportedControlFlow, "unsupported control transfer");
            }

            return Flow::Fallthrough;
        }

        class Discovery {
          public:
            Discovery(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                      const MCInstrInfo &info)
                : bytes(bytes), begin(begin), end(begin + static_cast<uint32_t>(bytes.size())),
                  dis(dis), info(info) {}

            ControlFlowGraph run();

          private:
            StringRef bytes;
            uint32_t begin, end;
            const MCDisassembler &dis;
            const MCInstrInfo &info;
            std::map<uint32_t, Step> decoded;
            // Keep the edge that introduced each leader for overlap diagnostics.
            std::map<uint32_t, uint32_t> leaders;
            std::vector<uint32_t> pending;
            void schedule(const Step &s, int64_t address);
            void trace(uint32_t start);
            void overlap(uint32_t target) const;
            ControlFlowGraph partition();
        };

        void Discovery::schedule(const Step &s, int64_t address) {
            if (address < begin || address >= end) {
                auto dest = address < 0 ? "-" + hex(static_cast<uint64_t>(-address))
                                        : hex(static_cast<uint64_t>(address));
                s.reject(FailureCode::UnsupportedControlFlow,
                         "control flow outside function to " + dest, address);
            }

            auto target = static_cast<uint32_t>(address);
            if (leaders.try_emplace(target, s.rva).second) {
                pending.push_back(target);
            }
        }

        void Discovery::overlap(uint32_t target) const {
            decoded.at(leaders.at(target))
                .reject(FailureCode::UnsupportedControlFlow,
                        "branch enters an instruction at " + hex(target), target);
        }

        void Discovery::trace(uint32_t start) {
            for (auto rva = start; rva < end;) {
                auto after = decoded.lower_bound(rva);
                if (after != decoded.end() && after->first == rva) {
                    return;
                }

                if (after != decoded.begin() && std::prev(after)->second.next > rva) {
                    overlap(rva);
                }

                auto s = decodeStep(bytes.drop_front(rva - begin), rva, dis, info);
                // A forward target may already be scheduled, even before its decode.
                auto leader = leaders.upper_bound(rva);
                if (leader != leaders.end() && leader->first < s.next) {
                    overlap(leader->first);
                }

                checkPrefix(s);
                auto flow = control(s, info);
                auto &step = decoded.emplace_hint(after, rva, std::move(s))->second;
                if (flow == Flow::Conditional || flow == Flow::Jump) {
                    schedule(step, int64_t(step.next) + step.inst.getOperand(0).getImm());

                    if (flow == Flow::Conditional) {
                        schedule(step, step.next);
                    }
                }

                if (flow != Flow::Fallthrough) {
                    return;
                }

                rva = step.next;
            }
        }

        ControlFlowGraph Discovery::partition() {
            ControlFlowGraph graph;
            for (const auto &[start, source] : leaders) {
                auto &block = graph[start];
                auto it = decoded.find(start);

                for (;;) {
                    auto &step = block.steps.emplace_back(std::move(it->second));
                    block.exit = control(step, info);
                    if (block.exit == Flow::Jump || block.exit == Flow::Conditional) {
                        block.successors.push_back(static_cast<uint32_t>(
                            int64_t(step.next) + step.inst.getOperand(0).getImm()));
                    }

                    if (block.exit == Flow::Conditional) {
                        block.successors.push_back(step.next);
                    }

                    if (block.exit != Flow::Fallthrough) {
                        break;
                    }

                    if (step.next == end) {
                        block.exit = Flow::FallOff;
                        break;
                    }

                    if (leaders.contains(step.next)) {
                        block.successors.push_back(step.next);
                        break;
                    }

                    ++it;
                }
            }

            return graph;
        }

        ControlFlowGraph Discovery::run() {
            leaders.emplace(begin, begin);
            pending.push_back(begin);
            while (!pending.empty()) {
                const auto start = pending.back();
                pending.pop_back();
                try {
                    trace(start);
                } catch (InspectionError &error) {
                    if (error.context.instructionRva) {
                        auto leader = std::prev(leaders.upper_bound(*error.context.instructionRva));
                        error.context.blockRva = leader->first;
                    }
                    throw;
                }
            }

            return partition();
        }
    } // namespace

    ControlFlowGraph discoverCFG(StringRef bytes, uint32_t begin, const MCDisassembler &dis,
                                 const MCInstrInfo &info) {
        if (bytes.size() > size_t{64} * 1024) {
            throw InspectionError(hex(begin) + ": experimental lift limit is 64 KiB per function",
                                  FailureCode::FunctionSize);
        }

        return Discovery(bytes, begin, dis, info).run();
    }
} // namespace forge::x86
