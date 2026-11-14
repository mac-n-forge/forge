#pragma once

#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace forge::x86 {
    // Each byte has a mark: zero for uninitialized, 0xff for concrete, or an
    // incoming nonvolatile byte identity. A null marks operand denotes all concrete.
    struct StoredValue {
        llvm::Value *bits;
        llvm::Value *marks = nullptr;
    };

    // IR storage belongs to the lifted function. The builder and its insertion
    // point are shared with instruction lowering, including guard continuations.
    class GuestStack {
      public:
        static constexpr uint64_t base = 0x70000000;
        static constexpr unsigned capacity = 4096;
        static constexpr uint64_t entryRsp = base + capacity - 32 - 8;

        explicit GuestStack(llvm::IRBuilder<> &builder) : ir(builder) {}

        void allocate();
        llvm::Value *load(llvm::Value *address, unsigned width);
        StoredValue loadSaved(llvm::Value *address, unsigned width);
        void store(llvm::Value *address, StoredValue value);
        void checkReturn(llvm::Value *rsp);
        void guard(llvm::Value *condition);

      private:
        llvm::IRBuilder<> &ir;
        llvm::Value *bytes = nullptr;
        llvm::Value *validity = nullptr;
        llvm::BasicBlock *fault = nullptr;

        llvm::Value *checkedOffset(llvm::Value *address, unsigned width);
        StoredValue loadAt(llvm::Value *offset, unsigned width, bool allowOpaque);
        void storeAt(llvm::Value *offset, StoredValue value);
    };
} // namespace forge::x86
