#pragma once
#include "address.h"
#include <intrin.h>

class StackFrame
{
public:
	StackFrame(std::uintptr_t ret)
	{
		this->base = ret - sizeof(std::uintptr_t);
	}

	Address GetFramePointer()
	{
		return this->base;
	}

	Address GetReturnAddress()
	{
		return this->base.Offset(sizeof(std::uintptr_t)).DerefSelf();
	}

	template <typename T>
	T GetVar(std::uintptr_t offset)
	{
		return (T)((uintptr_t)this->base.GetPtr() - offset);
	}

	template <typename T>
	T GetArg(std::uintptr_t offset)
	{
		return (T)((uintptr_t)this->base.GetPtr() + offset);
	}

	template <typename T>
	T GetArgValue(std::uintptr_t offset)
	{
		return this->base.Offset(offset).DerefSelf().Cast<T>();
	}

	StackFrame PreviousFrame(std::size_t deref = 1)
	{
		this->base.DerefSelf(deref);
		return *this;
	}
private:
	Address base;
};

#define STACKFRAME() auto STACK_FRAME = StackFrame((std::uintptr_t)_AddressOfReturnAddress());