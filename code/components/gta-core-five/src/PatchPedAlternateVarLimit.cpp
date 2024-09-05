#include <StdInc.h>

#include <Hooking.h>

#define COMPUTE_ALTERNATES_SIZE(__n) (((8 /* Aligned alternate struct size */ * __n) + 15) & ~15); // 16 bytes alignment

static constexpr const int kMaxNumAlternates = 512;

static constexpr const int kAlternatesSize = COMPUTE_ALTERNATES_SIZE(kMaxNumAlternates);

static HookFunction hookFunction([]
{
	auto prevMaxNumAlternates = *hook::get_pattern<uint16_t>("48 89 4D ? 45 8B C7", 0xF);

	auto prevAlternatesSize = COMPUTE_ALTERNATES_SIZE(prevMaxNumAlternates);

	{
		auto matches = hook::pattern(
			fmt::sprintf("B8 %02X %02X %02X %02X 48 2B",
				 prevAlternatesSize			& 0xFF,
				(prevAlternatesSize >> 8 )	& 0xFF,
				(prevAlternatesSize >> 16)	& 0xFF,
				(prevAlternatesSize >> 24)	& 0xFF
			))
			.count(5);

		for (size_t i = 0; i < matches.size(); i++)
		{
			auto location = matches.get(i).get<char>(0x1);

			hook::put<int32_t>(location, kAlternatesSize);
		}
	}

	{
		auto matches = hook::pattern(
			fmt::sprintf("C7 45 ? 00 00 %02X %02X",
				 prevMaxNumAlternates		& 0xFF,
				(prevMaxNumAlternates >> 8) & 0xFF
			))
			.count(5);

		for (size_t i = 0; i < matches.size(); i++)
		{
			auto location = matches.get(i).get<char>(0x5);

			hook::put<int16_t>(location, kMaxNumAlternates);
		}
	}
});
