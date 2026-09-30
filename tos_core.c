#include <math.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define TOS_API __declspec(dllexport)
#else
#define TOS_API __attribute__((visibility("default")))
#endif

static double entropy_from_counts(const uint32_t *counts, uint32_t total) {
    double entropy = 0.0;
    if (total == 0) {
        return 0.0;
    }
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) {
            continue;
        }
        double p = (double)counts[i] / (double)total;
        entropy -= p * (log(p) / log(2.0));
    }
    return entropy;
}

TOS_API double tos_conditional_entropy(const unsigned char *data, size_t size, int order) {
    if (data == NULL || size == 0) {
        return 0.0;
    }
    if (order <= 0 || size <= (size_t)order) {
        uint32_t counts[256] = {0};
        for (size_t i = 0; i < size; i++) {
            counts[data[i]]++;
        }
        return entropy_from_counts(counts, (uint32_t)size);
    }
    if (order > 2) {
        order = 2;
    }

    size_t context_count = (order == 1) ? 256u : 65536u;
    uint32_t *counts = (uint32_t *)calloc(context_count * 256u, sizeof(uint32_t));
    uint32_t *totals = (uint32_t *)calloc(context_count, sizeof(uint32_t));
    if (counts == NULL || totals == NULL) {
        free(counts);
        free(totals);
        return 0.0;
    }

    for (size_t i = (size_t)order; i < size; i++) {
        uint32_t context;
        if (order == 1) {
            context = data[i - 1];
        } else {
            context = ((uint32_t)data[i - 2] << 8) | data[i - 1];
        }
        totals[context]++;
        counts[(context * 256u) + data[i]]++;
    }

    uint32_t total = (uint32_t)(size - (size_t)order);
    double entropy = 0.0;
    for (size_t context = 0; context < context_count; context++) {
        if (totals[context] == 0) {
            continue;
        }
        double h = entropy_from_counts(&counts[context * 256u], totals[context]);
        entropy += ((double)totals[context] / (double)total) * h;
    }

    free(counts);
    free(totals);
    return entropy;
}

static uint64_t fnv1a64(const unsigned char *data, size_t size) {
    uint64_t value = 1469598103934665603ULL;
    for (size_t i = 0; i < size; i++) {
        value ^= (uint64_t)data[i];
        value *= 1099511628211ULL;
    }
    return value;
}

TOS_API uint64_t tos_simhash64(const unsigned char *data, size_t size, int shingle_size) {
    if (data == NULL || size == 0) {
        return 0;
    }
    if (shingle_size < 1) {
        shingle_size = 1;
    }

    int weights[64];
    memset(weights, 0, sizeof(weights));
    size_t span = (size < (size_t)shingle_size) ? size : (size_t)shingle_size;
    size_t end = (size < span) ? 1 : size - span + 1;
    for (size_t i = 0; i < end; i++) {
        uint64_t value = fnv1a64(data + i, span);
        for (int bit = 0; bit < 64; bit++) {
            weights[bit] += (value & (1ULL << bit)) ? 1 : -1;
        }
    }

    uint64_t signature = 0;
    for (int bit = 0; bit < 64; bit++) {
        if (weights[bit] >= 0) {
            signature |= 1ULL << bit;
        }
    }
    return signature;
}
