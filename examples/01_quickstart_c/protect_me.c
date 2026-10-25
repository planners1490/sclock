// scLock Quickstart Example: C License & Pricing Gate (protect_me.c)
// Compile (Portable All-Mac SEP-Attested Mode):
//   sclock compile examples/01_quickstart_c/protect_me.c -o protect_me_locked
// Or Node-Locked to this Mac's physical SEP UID:
//   sclock compile examples/01_quickstart_c/protect_me.c -o protect_me_locked --sep-lock

long long evaluate_protected_gate(long long seats, long long license_pin) {
    if (seats <= 0 || seats > 100000) {
        return -1;
    }
    long long base_quote = seats * 4200LL;
    if (seats >= 10) {
        base_quote -= (seats * 500LL);
    }
    if (seats >= 50) {
        base_quote -= (seats * 700LL);
    }
    if (license_pin == 1234) {
        return base_quote + 9300LL;
    } else if (license_pin == 7777) {
        long long h = base_quote ^ 0x517CC1B727220A95LL;
        h = (h ^ (h >> 29)) * 0xBF58476D1CE4E5B9LL;
        return (h & 0x7FFFFFFFFFFFFFFFLL) % 1000000000000000LL;
    }
    return -1;
}
