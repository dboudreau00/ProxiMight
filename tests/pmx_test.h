/* pmx_test.h — a minimal, dependency-free assertion harness. */
#ifndef PMX_TEST_H
#define PMX_TEST_H

#include <stdio.h>

static int pmx__checks = 0;
static int pmx__fails = 0;

#define CHECK(cond)                                                             \
    do {                                                                        \
        pmx__checks++;                                                          \
        if (!(cond)) {                                                          \
            pmx__fails++;                                                       \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                       \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                      \
    do {                                                                        \
        long _a = (long)(a), _b = (long)(b);                                    \
        pmx__checks++;                                                          \
        if (_a != _b) {                                                         \
            pmx__fails++;                                                       \
            fprintf(stderr, "  FAIL %s:%d: %s (%ld) != %s (%ld)\n", __FILE__,   \
                    __LINE__, #a, _a, #b, _b);                                  \
        }                                                                       \
    } while (0)

#define CHECK_STR_EQ(a, b)                                                      \
    do {                                                                        \
        pmx__checks++;                                                          \
        if (strcmp((a), (b)) != 0) {                                            \
            pmx__fails++;                                                       \
            fprintf(stderr, "  FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__,       \
                    __LINE__, (a), (b));                                        \
        }                                                                       \
    } while (0)

static int pmx_test_report(void) {
    printf("%d checks, %d failure(s)\n", pmx__checks, pmx__fails);
    return pmx__fails ? 1 : 0;
}

#endif /* PMX_TEST_H */
