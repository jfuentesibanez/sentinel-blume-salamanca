// Independent audit wrapper: arithmetic primitives only; never invokes IDP.
#include "../phase4_crypto/source_moves.h"
#define main phase15_unused_main
#include "../phase15_crypto/static_landscape.cpp"
#undef main

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    volatile float old_value = -6.898953914642334f;
    volatile float new_value = -2.495816469192505f;
    double legacy_update = old_value + (new_value - old_value);
    double promoted_update = double(old_value) + (double(new_value) - double(old_value));
    std::cout << std::setprecision(17)
              << "{\"kind\":\"sliding_primitive\",\"old\":" << old_value
              << ",\"new\":" << new_value << ",\"legacy_update\":" << legacy_update
              << ",\"promoted_update\":" << promoted_update << "}\n";
    for (int i = 1; i < argc; ++i) {
        Model model(argv[i]);
        ExactModel exact(model);
        std::cout << "{\"kind\":\"model_primitive\",\"path\":" << std::quoted(argv[i])
                  << ",\"shift\":" << exact.shift << ",\"scale\":" << exact.scale
                  << ",\"bound\":" << exact.bound(38, 20, 2) << ",\"numerators\":[";
        for (std::size_t j = 0; j < exact.b.size(); ++j) {
            if (j) std::cout << ',';
            std::cout << exact.b[j];
        }
        std::cout << "]}\n";
    }
    const std::array<int64_t, 3> denominators = {
        999999999999LL, 1000000000000LL, 1000000000001LL
    };
    for (auto denominator : denominators) {
        std::cout << "{\"kind\":\"epsilon_primitive\",\"candidate\":1,\"initial\":0,\"denominator\":"
                  << denominator << ",\"improves\":"
                  << (exact_improves(1, 0, denominator) ? "true" : "false") << "}\n";
    }
    std::cout << "{\"kind\":\"extreme_comparator\",\"positive\":"
              << (exact_improves(INT64_MAX, INT64_MIN, INT64_MAX) ? "true" : "false")
              << ",\"negative\":"
              << (exact_improves(INT64_MIN, INT64_MAX, INT64_MAX) ? "true" : "false")
              << "}\n";
    std::cout << "{\"kind\":\"meters\",\"legacy_calls\":" << backend_legacy_calls
              << ",\"exact_calls\":" << backend_exact_calls << "}\n";
    return backend_legacy_calls == 0 && backend_exact_calls == 0 ? 0 : 3;
}
