# pragma once
#include <bitset>

namespace hash_lib
{

    std::string SHA224(std::string);

    std::string SHA256(std::string);

    std::string SHA384(std::string);

    std::string SHA512(std::string);

    std::string SHA0(std::string);

    std::string SHA1(std::string);

    std::string MD4(std::string);

    std::string MD5(std::string);

    std::string ROT13(std::string);

    enum decimal_to_hex_system
	{
		x86 = 1,
		x64 = 2
	};

	enum output_type
	{
		LITTL_ENDIA = 1,
		BIG_ENDIA = 2
	};

    std::string decimal_to_hex(unsigned long long int,
                               hash_lib::decimal_to_hex_system = hash_lib::decimal_to_hex_system::x86,
							   hash_lib::output_type = hash_lib::output_type::BIG_ENDIA);

    template<size_t T>
	inline std::bitset<T> rightrotate(std::bitset<T>, unsigned);

	template<size_t T>
	inline std::bitset<T> leftrotate(std::bitset<T>, unsigned);




}
