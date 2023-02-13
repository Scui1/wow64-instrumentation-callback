#pragma once
#include <cstdint>
#include <cstddef>

class Address
{
private:
	std::uintptr_t ptr;
public:
	std::uintptr_t GetPtr() { return ptr; }

	Address() : ptr(0) {}
	Address(std::uintptr_t ptr) : ptr(ptr) {}
	Address(void* ptr) : ptr(std::uintptr_t(ptr)) {}

	operator std::uintptr_t() const
	{
		return ptr;
	}

	operator void* ()
	{
		return reinterpret_cast<void*>(ptr);
	}

	operator bool()
	{
		return ptr != NULL;
	}

	bool operator== (const Address& other) const
	{
		return ptr == other.ptr;
	}

	bool operator!= (const Address& other) const
	{
		return ptr != other.ptr;
	}

	bool operator== (const uintptr_t& other) const
	{
		return ptr == other;
	}

	template<typename T> T Cast()
	{
		return (T)ptr;
	}

	template<typename T> T GetSelf(int timesToDeref = 1)
	{
		DerefSelf(timesToDeref);
		return Cast<T>();
	}

	template<typename T> T Get(int timesToDeref = 1)
	{
		return Deref(timesToDeref).Cast<T>();
	}

	Address Offset(std::ptrdiff_t offset)
	{
		return Address(ptr + offset);
	}

	Address OffsetSelf(std::ptrdiff_t offset)
	{
		ptr += offset;
		return *this;
	}

	Address Deref(int timesToDeref = 1)
	{
		std::uintptr_t dummy = ptr;

		while (timesToDeref--)
		{
			if (dummy)
				dummy = *reinterpret_cast<uintptr_t*>(dummy);
		}

		return Address(dummy);
	}

	Address DerefSelf(int timesToDeref = 1)
	{
		while (timesToDeref--)
		{
			if (ptr)
				ptr = *reinterpret_cast<uintptr_t*>(ptr);
		}

		return *this;
	}

	Address FollowJmp(std::ptrdiff_t offset = 0x1)
	{
		std::uintptr_t base = ptr + offset;

		//Skipping 0xE9 opcode and read the 4-byte relative address
		std::int32_t relAddress = *reinterpret_cast<std::int32_t*>(base);

		//Skipping the 0xE9 opcode and the relative address bytes and add the relative address to it
		return Address(ptr + 0x5 + relAddress);
	}

	Address FollowJmpSelf(std::ptrdiff_t offset = 0x1)
	{
		std::uintptr_t base = ptr + offset;

		//Skipping 0xE8 opcode and read the 4-byte relative address
		std::int32_t relAddress = *reinterpret_cast<std::int32_t*>(base);

		//Skipping the 0xE9 opcode and the relative address bytes and add the relative address to it
		ptr += 0x5 + relAddress;
		return *this;
	}

	Address FollowShortJmp(std::ptrdiff_t offset = 0x1)
	{
		std::uintptr_t base = ptr + offset;

		//Skipping 0xEB opcode and read the 4-byte relative address
		std::int8_t relAddress = *reinterpret_cast<std::int8_t*>(base);

		//Skipping the 0xEB opcode and the relative address bytes and add the relative address to it
		return Address(ptr + 0x2 + relAddress);
	}

	Address FollowShortJmpSelf(std::ptrdiff_t offset = 0x1)
	{
		std::uintptr_t base = ptr + offset;

		//Skipping 0xEB opcode and read the 4-byte relative address
		std::int8_t relAddress = *reinterpret_cast<std::int8_t*>(base);

		//Skipping the 0xEB opcode and the relative address bytes and add the relative address to it
		ptr += 0x2 + relAddress;
		return *this;
	}

	bool CheckOpcode(unsigned char opcode)
	{
		return *reinterpret_cast<unsigned char*>(ptr) == opcode;
	}

	template<class T> int GetVFuncIndex()
	{
		return *reinterpret_cast<T*>(ptr) / 4;
	}

	template<class T> T GetValue()
	{
		return *reinterpret_cast<T*>(ptr);
	}
};