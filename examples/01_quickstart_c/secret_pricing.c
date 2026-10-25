// scLock Quickstart Example: Commercial License & Dynamic Pricing Algorithm
// Compile with:
//   ../../bin/sclock compile secret_pricing.c -o secret_pricing_locked --entry calc_license_tier

typedef long long i64;
typedef unsigned long long u64;

__attribute__((export_name("calc_license_tier")))
i64 calc_license_tier(i64 seats, i64 unlock_pin) {
    if (seats <= 0) return 0;
    // Secret commercial pricing & feature unlock formula
    u64 base = (u64)seats * 4900ULL;
    u64 discount = (seats >= 10) ? ((base * 15ULL) / 100ULL) : 0ULL;
    u64 net_price = base - discount;

    // Only unlock Pro multiplier if unlock_pin == 7777
    if (unlock_pin == 7777) {
        u64 token = ((net_price ^ 0x53434C4F434BULL) * 2654435761ULL) & 0xFFFFFFFFULL;
        return (i64)(net_price * 10000000000ULL + token);
    }
    return (i64)net_price;
}
