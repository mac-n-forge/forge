#include "lift/stack.h"

#include "llvm/IR/Intrinsics.h"

namespace forge::x86 {
    using namespace llvm;

    void GuestStack::allocate() {
        bytes = ir.CreateAlloca(ir.getInt8Ty(), ir.getInt32(capacity), "stack.bytes");
        validity = ir.CreateAlloca(ir.getInt8Ty(), ir.getInt32(capacity), "stack.valid");
        ir.CreateMemSet(validity, ir.getInt8(0), capacity, Align(1));
    }

    void GuestStack::guard(Value *condition) {
        auto *function = ir.GetInsertBlock()->getParent();

        if (!fault) {
            IRBuilderBase::InsertPointGuard restore(ir);
            fault = BasicBlock::Create(ir.getContext(), "stack.fault", function);
            ir.SetInsertPoint(fault);
            ir.CreateIntrinsic(Intrinsic::trap, {});
            ir.CreateUnreachable();
        }

        auto *next = BasicBlock::Create(ir.getContext(), "stack.ok", function);
        ir.CreateCondBr(condition, next, fault);
        ir.SetInsertPoint(next);
    }

    Value *GuestStack::checkedOffset(Value *address, unsigned width) {
        const unsigned size = width / 8;
        auto *offset = ir.CreateSub(address, ir.getInt64(base));
        auto *mapped = ir.CreateICmpULE(offset, ir.getInt64(capacity - size));
        constexpr auto returnOffset = entryRsp - base;
        auto *below = ir.CreateICmpULE(offset, ir.getInt64(returnOffset - size));
        auto *above = ir.CreateICmpUGE(offset, ir.getInt64(returnOffset + 8));
        guard(ir.CreateAnd(mapped, ir.CreateOr(below, above)));

        return offset;
    }

    Value *GuestStack::load(Value *address, unsigned width) {
        auto *offset = checkedOffset(address, width);
        auto *type = ir.getIntNTy(width);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        auto *initialized = ir.CreateAlignedLoad(type, marks, Align(1));
        guard(ir.CreateICmpEQ(initialized, ConstantInt::getAllOnesValue(type)));

        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        return ir.CreateAlignedLoad(type, data, Align(1));
    }

    void GuestStack::store(Value *address, Value *value) {
        auto *type = value->getType();
        auto *offset = checkedOffset(address, type->getIntegerBitWidth());
        auto *data = ir.CreateInBoundsGEP(ir.getInt8Ty(), bytes, offset);
        auto *marks = ir.CreateInBoundsGEP(ir.getInt8Ty(), validity, offset);
        ir.CreateAlignedStore(value, data, Align(1));
        ir.CreateAlignedStore(ConstantInt::getAllOnesValue(type), marks, Align(1));
    }

    void GuestStack::checkReturn(Value *rsp) { guard(ir.CreateICmpEQ(rsp, ir.getInt64(entryRsp))); }
} // namespace forge::x86
