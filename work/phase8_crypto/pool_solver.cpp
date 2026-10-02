// Instrumented, bounded comparison. Inputs contain ciphertext only.
// Frozen cryptographic primitives and audited source movements are imported.
#include "../phase4_crypto/source_moves.h"

namespace phase8 {
using Clock = std::chrono::steady_clock;
double elapsed(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}
const char* boolean(bool value) { return value ? "true" : "false"; }
struct Budget {
    double seconds;
    long maximum, used = 0;
    bool cut = false;
    std::string cause = "algorithm_finished";
    Clock::time_point start = Clock::now();
    bool allow() {
        const bool evaluations = used >= maximum;
        const bool wall = elapsed(start) > seconds;
        if (evaluations || wall) {
            cut = true;
            cause = evaluations && wall ? "evaluations_and_wall_time"
                  : evaluations ? "evaluations" : "wall_time";
            return false;
        }
        ++used;
        return true;
    }
};
struct Stage {
    long evaluations = 0, feature_evaluations = 0, q_evaluations = 0;
    long initial_q_evaluations = 0;
    int restarts_attempted = 0, restarts_completed = 0;
    double seconds = 0, setup_seconds = 0;
    bool cut = false;
    std::string cause = "algorithm_finished", cut_phase = "none";
    double seconds_limit = 0;
    long evaluations_limit = 0;
};
void finish(Stage& stage, const Budget& budget) {
    stage.evaluations = budget.used;
    stage.seconds = elapsed(budget.start);
    stage.cut = budget.cut;
    stage.cause = budget.cause;
    stage.seconds_limit = budget.seconds;
    stage.evaluations_limit = budget.maximum;
}
std::string stage_json(const Stage& stage) {
    std::ostringstream out;
    out << std::setprecision(12)
        << "{\"evaluations\":" << stage.evaluations
        << ",\"feature_evaluations\":" << stage.feature_evaluations
        << ",\"q_evaluations\":" << stage.q_evaluations
        << ",\"initial_q_evaluations\":" << stage.initial_q_evaluations
        << ",\"restarts_attempted\":" << stage.restarts_attempted
        << ",\"restarts_completed\":" << stage.restarts_completed
        << ",\"seconds\":" << stage.seconds
        << ",\"setup_seconds\":" << stage.setup_seconds
        << ",\"seconds_limit\":" << stage.seconds_limit
        << ",\"evaluations_limit\":" << stage.evaluations_limit
        << ",\"cut\":" << boolean(stage.cut)
        << ",\"cause\":\"" << stage.cause
        << "\",\"cut_phase\":\"" << stage.cut_phase << "\"}";
    return out.str();
}

struct K2Stage {
    std::vector<std::pair<double, V>> candidates;
    Stage stage;
    long pool_evaluations = 0, swap_evaluations = 0, hill_evaluations = 0;
    int climbs_attempted = 0, climbs_completed = 0;
    int duplicate_candidates_removed = 0;
};
K2Stage k2_search(const Ms& ciphertext, int w1, int w2, const Model& model,
                  uint64_t seed, double seconds, long maximum) {
    Budget budget{seconds, maximum};
    K2Stage result;
    RNG rng(seed);
    auto score = [&](const V& key) {
        return idp(undo2(ciphertext, inverse(key), 0), w1, 0, model, -1, true);
    };
    std::vector<std::pair<double, V>> keys;
    auto sort_keys = [&]() {
        std::sort(keys.begin(), keys.end(), [](const auto& a, const auto& b) {
            return a.first > b.first;
        });
    };
    for (int i = 0; i < 1000; ++i) {
        if (!budget.allow()) { result.stage.cut_phase = "random_pool"; break; }
        V key = perm(w2, rng);
        keys.push_back({score(key), key});
        ++result.pool_evaluations;
    }
    if (keys.empty()) throw std::runtime_error("K2 pool empty");
    sort_keys();
    if (keys.size() > 20) keys.resize(20);
    for (auto& item : keys) {
        V key = item.second;
        double current = item.first;
        for (int i = 0; i < w2 - 1 && !budget.cut; ++i) {
            for (int j = i + 1; j < w2; ++j) {
                if (!budget.allow()) { result.stage.cut_phase = "left_to_right_swaps"; break; }
                V candidate = key;
                std::swap(candidate[i], candidate[j]);
                double value = score(candidate);
                ++result.swap_evaluations;
                if (value > current + 1e-12) { current = value; key = candidate; }
            }
        }
        item = {current, key};
    }
    sort_keys();
    if (keys.size() > 5) keys.resize(5);
    auto movements = source_moves(w2);
    for (auto& item : keys) {
        if (budget.cut) break;
        ++result.climbs_attempted;
        V key = item.second;
        double current = item.first;
        bool improved = true;
        while (improved && !budget.cut) {
            improved = false;
            std::shuffle(movements.begin(), movements.end(), rng);
            for (const auto& movement : movements) {
                if (!budget.allow()) { result.stage.cut_phase = "source_hill_climb"; break; }
                V candidate = moved(key, movement);
                const double value = score(candidate);
                ++result.hill_evaluations;
                if (value > current + 1e-12) {
                    current = value; key = candidate; improved = true;
                }
            }
        }
        item = {current, key};
        if (!budget.cut) ++result.climbs_completed;
    }
    sort_keys();
    for (auto& item : keys) {
        item.second = inverse(item.second);
        bool duplicate = false;
        for (const auto& previous : result.candidates) {
            if (previous.second == item.second) duplicate = true;
        }
        if (duplicate) ++result.duplicate_candidates_removed;
        else result.candidates.push_back(item);
    }
    finish(result.stage, budget);
    return result;
}

struct K1Stage { V key; double score = -1e100; Stage stage; };
K1Stage k1_search(const Ms& intermediate, int width, const Model& model,
                  uint64_t seed, int restarts, double seconds, long maximum) {
    Budget budget{seconds, maximum}; // Starts before ICT tables are constructed.
    ICT ict(intermediate, width, model, true);
    auto movements = moves(width);
    K1Stage result;
    result.stage.setup_seconds = elapsed(budget.start);
    RNG rng(seed);
    for (int restart = 0; restart < restarts && !budget.cut; ++restart) {
        ++result.stage.restarts_attempted;
        V key = perm(width, rng);
        Feature current = ict.feature(key);
        double adjacency_threshold = current.adj, alignment_threshold = 0;
        for (int round = 0; round < 15 && !budget.cut; ++round) {
            bool cycle_improved = false;
            for (int primary = 0; primary < 2 && !budget.cut; ++primary) {
                bool improved = true;
                int sweeps = 0;
                while (improved && sweeps++ < 15 && !budget.cut) {
                    improved = false;
                    for (const auto& movement : movements) {
                        if (!budget.allow()) { result.stage.cut_phase = "feature_search"; break; }
                        V candidate = moved(key, movement);
                        const Feature feature = ict.feature(candidate);
                        ++result.stage.feature_evaluations;
                        const bool accept = primary == 0
                            ? ((feature.adj > current.adj + 1e-12 || (std::abs(feature.adj - current.adj) < 1e-12 && feature.align > current.align)) && feature.align >= alignment_threshold)
                            : ((feature.align > current.align || (feature.align == current.align && feature.adj > current.adj + 1e-12)) && feature.adj >= adjacency_threshold);
                        if (accept) { key = candidate; current = feature; improved = cycle_improved = true; }
                    }
                }
            }
            adjacency_threshold = std::max(adjacency_threshold, adjacency_threshold + .25 * (current.adj - adjacency_threshold));
            alignment_threshold = std::max(alignment_threshold, alignment_threshold + .25 * (current.align - alignment_threshold));
            if (!cycle_improved) break;
        }
        // Same initial-score operation as frozen K1; counted separately from
        // capped proposal evaluations. Its elapsed time stays in this stage.
        double value = ict.qscore(key, 3);
        ++result.stage.initial_q_evaluations;
        bool improved = true;
        while (improved && !budget.cut) {
            improved = false;
            for (const auto& movement : movements) {
                if (!budget.allow()) { result.stage.cut_phase = "plaintext_hill_climb"; break; }
                V candidate = moved(key, movement);
                const double candidate_value = ict.qscore(candidate, 3);
                ++result.stage.q_evaluations;
                if (candidate_value > value + 1e-12) { value = candidate_value; key = candidate; improved = true; }
            }
        }
        if (value > result.score) { result.score = value; result.key = inverse(key); }
        if (!budget.cut) ++result.stage.restarts_completed;
    }
    if (result.key.empty()) throw std::runtime_error("K1 result empty");
    finish(result.stage, budget);
    return result;
}

struct FinalStage { V key; double score; Stage stage; };
FinalStage adjust_k2(const Ms& ciphertext, const V& k1, const V& start,
                     const Model& model, uint64_t seed, double seconds, long maximum) {
    Budget budget{seconds, maximum};
    FinalStage result;
    auto movements = source_moves(static_cast<int>(start.size()));
    result.stage.setup_seconds = elapsed(budget.start);
    RNG rng(seed);
    V key = inverse(start);
    auto score = [&](const V& candidate) { return fullscore(ciphertext, k1, inverse(candidate), 0, model, 3); };
    double current = score(key);
    result.stage.initial_q_evaluations = 1;
    bool improved = true;
    while (improved && !budget.cut) {
        improved = false;
        std::shuffle(movements.begin(), movements.end(), rng);
        for (const auto& movement : movements) {
            if (!budget.allow()) { result.stage.cut_phase = "plaintext_hill_climb"; break; }
            V candidate = moved(key, movement);
            const double value = score(candidate);
            ++result.stage.q_evaluations;
            if (value > current + 1e-12) { current = value; key = candidate; improved = true; }
        }
    }
    result.key = inverse(key);
    result.score = current;
    finish(result.stage, budget);
    return result;
}

struct CandidateTrace {
    int round, pool_rank;
    double pool_idp;
    V start_k2;
    K1Stage k1;
    FinalStage final;
};
struct PolicyResult {
    std::string policy;
    int selected_round = -1, selected_pool_rank = -1;
    double score = -1e100, dependent_seconds = 0;
    long dependent_evaluations = 0, dependent_initial_q_evaluations = 0;
    V k1, k2;
    std::vector<CandidateTrace> candidates;
};
PolicyResult evaluate_policy(const Ms& ciphertext, int w1, const Model& model,
                             uint64_t search_seed, const std::vector<K2Stage>& pools,
                             int maximum_candidates, double k1_seconds,
                             double final_seconds, long k1_maximum, long final_maximum) {
    PolicyResult result;
    result.policy = maximum_candidates == 1 ? "single" : "pool5";
    const auto start = Clock::now();
    for (int round = 0; round < 3; ++round) {
        const uint64_t round_seed = search_seed + uint64_t(round) * 0x9e3779b97f4a7c15ULL;
        const int count = std::min(maximum_candidates, static_cast<int>(pools[round].candidates.size()));
        for (int rank = 0; rank < count; ++rank) {
            const auto& planted_free_candidate = pools[round].candidates[rank];
            CandidateTrace trace;
            trace.round = round;
            trace.pool_rank = rank + 1;
            trace.pool_idp = planted_free_candidate.first;
            trace.start_k2 = planted_free_candidate.second;
            const uint64_t candidate_offset = uint64_t(rank) * 0xd1b54a32d192ed03ULL;
            trace.k1 = k1_search(undo2(ciphertext, trace.start_k2, 0), w1, model,
                                (round_seed ^ 0x1111111111111111ULL) + candidate_offset,
                                8, k1_seconds / count, k1_maximum / count);
            trace.final = adjust_k2(ciphertext, trace.k1.key, trace.start_k2, model,
                                   (round_seed ^ 0x3333333333333333ULL) + candidate_offset,
                                   final_seconds / count, final_maximum / count);
            result.dependent_evaluations += trace.k1.stage.evaluations + trace.final.stage.evaluations;
            result.dependent_initial_q_evaluations += trace.k1.stage.initial_q_evaluations + trace.final.stage.initial_q_evaluations;
            if (trace.final.score > result.score) {
                result.score = trace.final.score;
                result.k1 = trace.k1.key;
                result.k2 = trace.final.key;
                result.selected_round = round;
                result.selected_pool_rank = rank + 1;
            }
            result.candidates.push_back(trace);
        }
    }
    result.dependent_seconds = elapsed(start);
    return result;
}

void emit_policy(const PolicyResult& result, const std::vector<K2Stage>& pools,
                  const Ms& ciphertext, int w1, int w2, uint64_t search_seed,
                  double k1_seconds, double k2_seconds, double final_seconds,
                  long k1_maximum, long k2_maximum, long final_maximum) {
    double shared_seconds = 0;
    long shared_evaluations = 0;
    bool reencryption = true;
    for (const auto& stage : pools) { shared_seconds += stage.stage.seconds; shared_evaluations += stage.stage.evaluations; }
    for (const auto& text : ciphertext) {
        auto recovered = crypt(text, result.k1, result.k2, 0, false);
        reencryption &= crypt(recovered, result.k1, result.k2, 0, true) == text;
    }
    std::cout << std::setprecision(12)
        << "{\"mode\":\"ciphertext_only_comparison\",\"policy\":\"" << result.policy
        << "\",\"messages_scored\":2,\"lengths\":[615,160],\"convention\":0,\"w1\":" << w1
        << ",\"w2\":" << w2 << ",\"search_seed\":" << search_seed
        << ",\"k1_seconds_per_round\":" << k1_seconds << ",\"k2_seconds_per_round\":" << k2_seconds
        << ",\"final_k2_seconds_per_round\":" << final_seconds
        << ",\"k1_evaluations_per_round\":" << k1_maximum << ",\"k2_evaluations_per_round\":" << k2_maximum
        << ",\"final_k2_evaluations_per_round\":" << final_maximum
        << ",\"k2_cache_charged_seconds\":" << shared_seconds
        << ",\"k2_cache_charged_evaluations\":" << shared_evaluations
        << ",\"dependent_seconds\":" << result.dependent_seconds
        << ",\"dependent_evaluations\":" << result.dependent_evaluations
        << ",\"dependent_initial_q_evaluations\":" << result.dependent_initial_q_evaluations
        << ",\"charged_total_seconds\":" << shared_seconds + result.dependent_seconds
        << ",\"charged_total_evaluations\":" << shared_evaluations + result.dependent_evaluations
        << ",\"q3\":" << result.score << ",\"k1\":" << keyjson(result.k1) << ",\"k2\":" << keyjson(result.k2)
        << ",\"selected_round\":" << result.selected_round << ",\"selected_pool_rank\":" << result.selected_pool_rank
        << ",\"reencryption_consistency\":" << boolean(reencryption) << ",\"rounds\":[";
    for (int round = 0; round < 3; ++round) {
        if (round) std::cout << ',';
        const auto& pool = pools[round];
        std::cout << "{\"round\":" << round << ",\"k2_stage\":" << stage_json(pool.stage)
            << ",\"pool_evaluations\":" << pool.pool_evaluations << ",\"swap_evaluations\":" << pool.swap_evaluations
            << ",\"hill_evaluations\":" << pool.hill_evaluations
            << ",\"climbs_attempted\":" << pool.climbs_attempted << ",\"climbs_completed\":" << pool.climbs_completed
            << ",\"duplicates_removed\":" << pool.duplicate_candidates_removed << ",\"pool\":[";
        for (std::size_t rank = 0; rank < pool.candidates.size(); ++rank) {
            if (rank) std::cout << ',';
            std::cout << "{\"rank\":" << rank + 1 << ",\"idp\":" << pool.candidates[rank].first
                      << ",\"k2\":" << keyjson(pool.candidates[rank].second) << '}';
        }
        std::cout << "]}";
    }
    std::cout << "],\"candidate_traces\":[";
    for (std::size_t i = 0; i < result.candidates.size(); ++i) {
        if (i) std::cout << ',';
        const auto& candidate = result.candidates[i];
        std::cout << "{\"round\":" << candidate.round << ",\"pool_rank\":" << candidate.pool_rank
            << ",\"pool_idp\":" << candidate.pool_idp << ",\"start_k2\":" << keyjson(candidate.start_k2)
            << ",\"k1\":" << keyjson(candidate.k1.key) << ",\"after_k1_q3\":" << candidate.k1.score
            << ",\"final_k2\":" << keyjson(candidate.final.key) << ",\"final_q3\":" << candidate.final.score
            << ",\"k1_stage\":" << stage_json(candidate.k1.stage)
            << ",\"final_k2_stage\":" << stage_json(candidate.final.stage) << '}';
    }
    std::cout << "]}\n" << std::flush;
}
} // namespace phase8

int main(int argc, char** argv) {
    try {
        if (argc != 13) throw std::runtime_error("pool_solver MODEL CT1 CT2 W1 W2 SEARCH_SEED K1_SECONDS K2_SECONDS FINAL_SECONDS K1_EVALS K2_EVALS FINAL_EVALS");
        Model model(argv[1]);
        Ms ciphertext = {read(argv[2]), read(argv[3])};
        const int w1 = std::stoi(argv[4]), w2 = std::stoi(argv[5]);
        const uint64_t search_seed = std::stoull(argv[6]);
        const double k1_seconds = std::stod(argv[7]), k2_seconds = std::stod(argv[8]), final_seconds = std::stod(argv[9]);
        const long k1_maximum = std::stol(argv[10]), k2_maximum = std::stol(argv[11]), final_maximum = std::stol(argv[12]);
        if (ciphertext[0].size() != 615 || ciphertext[1].size() != 160 || w1 < 3 || w2 < 3 || w1 > 160 || w2 > 160 || k1_maximum < 5 || k2_maximum < 5 || final_maximum < 5 || !(k1_seconds > 0) || !(k2_seconds > 0) || !(final_seconds > 0) || !std::isfinite(k1_seconds) || !std::isfinite(k2_seconds) || !std::isfinite(final_seconds)) throw std::runtime_error("invalid lengths, widths or budgets");
        // No ground-truth object, oracle flag, holdout path or truth score is
        // accepted here. K2 generation is shared before either policy runs.
        std::vector<phase8::K2Stage> pools;
        for (int round = 0; round < 3; ++round) {
            const uint64_t round_seed = search_seed + uint64_t(round) * 0x9e3779b97f4a7c15ULL;
            pools.push_back(phase8::k2_search(ciphertext, w1, w2, model,
                              round_seed ^ 0x2222222222222222ULL, k2_seconds, k2_maximum));
        }
        for (int count : {1, 5}) {
            const auto result = phase8::evaluate_policy(ciphertext, w1, model, search_seed, pools,
                                count, k1_seconds, final_seconds, k1_maximum, final_maximum);
            phase8::emit_policy(result, pools, ciphertext, w1, w2, search_seed,
                                k1_seconds, k2_seconds, final_seconds, k1_maximum, k2_maximum, final_maximum);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
