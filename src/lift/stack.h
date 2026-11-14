#pragma once

#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace forge::x86 {
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
        void store(llvm::Value *address, llvm::Value *value);
        void checkReturn(llvm::Value *rsp);

      private:
        llvm::IRBuilder<> &ir;
        llvm::Value *bytes = nullptr;
        llvm::Value *validity = nullptr;
        llvm::BasicBlock *fault = nullptr;

        void guard(llvm::Value *condition);
        llvm::Value *checkedOffset(llvm::Value *address, unsigned width);
    };
} // namespace forge::x86
