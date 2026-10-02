// External audit helper only. Never invoked by the search solver.
// Reconstructs RNG consumption used by the frozen CLI's plant() function.
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <random>
#include <vector>

void print_key(const std::vector<int>& key) {
    std::cout << '[';
    for (std::size_t i = 0; i < key.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << key[i];
    }
    std::cout << ']';
}

int main(int argc, char** argv) {
    if (argc != 5) return 1;
    const auto seed = std::stoull(argv[1]);
    const auto length = std::stoull(argv[2]);
    const int w1 = std::stoi(argv[3]), w2 = std::stoi(argv[4]);
    if (length < 775) return 2;
    std::mt19937_64 rng(seed);
    const auto position = rng() % (length - 774);
    std::vector<int> k1(w1), k2(w2);
    std::iota(k1.begin(), k1.end(), 0);
    std::iota(k2.begin(), k2.end(), 0);
    std::shuffle(k1.begin(), k1.end(), rng);
    std::shuffle(k2.begin(), k2.end(), rng);
    std::cout << "{\"sample_position\":" << position << ",\"true_k1\":";
    print_key(k1);
    std::cout << ",\"true_k2\":";
    print_key(k2);
    std::cout << "}\n";
}
