/*
 * Copyright (c) 2014 Nicolas Martyanoff
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "http.h"
#include "internal.h"

#include "tests.h"

#define HTTPT_BEGIN_RANGE_SET(str_, nb_ranges_)                         \
    do {                                                                \
        if (http_range_set_parse(&set, str_) == -1)                     \
            TEST_ABORT("cannot parse range set: %s", http_get_error()); \
        TEST_UINT_EQ(set.nb_ranges, nb_ranges_);                        \
    } while (0)

#define HTTPT_END_RANGE_SET() \
    http_range_set_free(&set)

#define HTTPT_INVALID_RANGE_SET(str_)                                   \
    do {                                                                \
        if (http_range_set_parse(&set, str_) == 0)                      \
            TEST_ABORT("parsed invalid range set");                     \
    } while (0)

TEST(simple_range) {
    struct http_range_set set;

    HTTPT_BEGIN_RANGE_SET("bytes=0-5", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 5);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("\t  bytes  =\t0 \t - 5  \t", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 5);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("bytes=15-100", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 15);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 100);
    HTTPT_END_RANGE_SET();
}

TEST(no_first) {
    struct http_range_set set;

    HTTPT_BEGIN_RANGE_SET("bytes=-5", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, false);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 5);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("\t  bytes  =\t \t - 5  \t", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, false);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 5);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("bytes=-100", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, false);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 100);
    HTTPT_END_RANGE_SET();
}

TEST(no_last) {
    struct http_range_set set;

    HTTPT_BEGIN_RANGE_SET("bytes=0-", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, false);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("\t  bytes  =\t0 \t -   \t", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, false);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("bytes=15-", 1);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 15);
    TEST_BOOL_EQ(set.ranges[0].has_last, false);
    HTTPT_END_RANGE_SET();
}

TEST(multiple_ranges) {
    struct http_range_set set;

    HTTPT_BEGIN_RANGE_SET("bytes=0-5,10-100\t,  2000-25000", 3);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, true);
    TEST_UINT_EQ(set.ranges[0].last, 5);

    TEST_BOOL_EQ(set.ranges[1].has_first, true);
    TEST_UINT_EQ(set.ranges[1].first, 10);
    TEST_BOOL_EQ(set.ranges[1].has_last, true);
    TEST_UINT_EQ(set.ranges[1].last, 100);

    TEST_BOOL_EQ(set.ranges[2].has_first, true);
    TEST_UINT_EQ(set.ranges[2].first, 2000);
    TEST_BOOL_EQ(set.ranges[2].has_last, true);
    TEST_UINT_EQ(set.ranges[2].last, 25000);
    HTTPT_END_RANGE_SET();

    HTTPT_BEGIN_RANGE_SET("bytes=0-,-100\t,  2000-", 3);
    TEST_INT_EQ(set.unit, HTTP_RANGE_UNIT_BYTES);
    TEST_BOOL_EQ(set.ranges[0].has_first, true);
    TEST_UINT_EQ(set.ranges[0].first, 0);
    TEST_BOOL_EQ(set.ranges[0].has_last, false);

    TEST_BOOL_EQ(set.ranges[1].has_first, false);
    TEST_BOOL_EQ(set.ranges[1].has_last, true);
    TEST_UINT_EQ(set.ranges[1].last, 100);

    TEST_BOOL_EQ(set.ranges[2].has_first, true);
    TEST_UINT_EQ(set.ranges[2].first, 2000);
    TEST_BOOL_EQ(set.ranges[2].has_last, false);
    HTTPT_END_RANGE_SET();
}

TEST(invalid) {
    struct http_range_set set;

    HTTPT_INVALID_RANGE_SET("");
    HTTPT_INVALID_RANGE_SET(" ");
    HTTPT_INVALID_RANGE_SET("foo");
    HTTPT_INVALID_RANGE_SET("bytes=");
    HTTPT_INVALID_RANGE_SET("bytes=-");
    HTTPT_INVALID_RANGE_SET("bytes=foo");
    HTTPT_INVALID_RANGE_SET("bytes=0");
    HTTPT_INVALID_RANGE_SET("bytes=-");
    HTTPT_INVALID_RANGE_SET("bytes=,");
    HTTPT_INVALID_RANGE_SET("bytes=0x-1");
    HTTPT_INVALID_RANGE_SET("bytes=0-1x");
    HTTPT_INVALID_RANGE_SET("bytes=0/1");
    HTTPT_INVALID_RANGE_SET("bytes=5-0");
    HTTPT_INVALID_RANGE_SET("bytes=0-5,");
    HTTPT_INVALID_RANGE_SET("bytes=0-5,  ");
}

TEST(simplify) {
    struct http_range_set set, sset;

#define HTTPT_BEGIN_SIMPLIFIED_RANGE_SET(str_, nb_ranges_, entity_sz_,  \
                                         nb_sranges_)                   \
    do {                                                                \
        if (http_range_set_parse(&set, str_) == -1)                     \
            TEST_ABORT("cannot parse range set: %s", http_get_error()); \
        TEST_UINT_EQ(set.nb_ranges, nb_ranges_);                        \
        http_range_set_simplify(&set, entity_sz_, &sset);               \
        TEST_UINT_EQ(sset.nb_ranges, nb_sranges_);                      \
    } while (0)

#define HTTPT_END_SIMPLIFIED_RANGE_SET() \
    do {                                 \
        http_range_set_free(&set);       \
        http_range_set_free(&sset);      \
    } while (0)

#define HTTPT_SIMPLIFIED_RANGE_EQ(range_, first_, last_) \
    do {                                                 \
        TEST_BOOL_EQ((range_)->has_first, true);         \
        TEST_UINT_EQ((range_)->first, first_);           \
        TEST_BOOL_EQ((range_)->has_last, true);          \
        TEST_UINT_EQ((range_)->last, last_);             \
    } while (0)

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-10", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 10);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-19", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-25", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=-10", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 10, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=-20", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=-30", 1, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-10,15-19", 2, 20, 2);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 10);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[1], 15, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-10,5-19", 2, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-12,-4", 2, 20, 2);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 12);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[1], 16, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-12,-10", 2, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=10-,12-14,-5", 3, 20, 1);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 10, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-3,5-12,10-14,16-18", 4, 20, 3);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 3);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[1], 5, 14);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[2], 16, 18);
    HTTPT_END_SIMPLIFIED_RANGE_SET();

    HTTPT_BEGIN_SIMPLIFIED_RANGE_SET("bytes=0-3,5-8,14-16,-4", 4, 20, 3);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[0], 0, 3);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[1], 5, 8);
    HTTPT_SIMPLIFIED_RANGE_EQ(&sset.ranges[2], 14, 19);
    HTTPT_END_SIMPLIFIED_RANGE_SET();
}

TEST(unsatisfiable) {
    struct http_range_set set;

#define HTTPT_RANGE_SET_IS_SATISFIABLE(str_, nb_ranges_, entity_sz_,    \
                                       is_satisfiable_)                 \
    do {                                                                \
        if (http_range_set_parse(&set, str_) == -1)                     \
            TEST_ABORT("cannot parse range set: %s", http_get_error()); \
        TEST_UINT_EQ(set.nb_ranges, nb_ranges_);                        \
        TEST_BOOL_EQ(http_range_set_is_satisfiable(&set, entity_sz_),   \
                     is_satisfiable_);                                  \
        http_range_set_free(&set);                                      \
    } while (0)

    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=0-0", 1, 20, true);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=19-19", 1, 20, true);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=19-20", 1, 20, true);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=0-20", 1, 20, true);

    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=20-25", 1, 20, false);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=24-25", 1, 20, false);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=0-5", 1, 0, false);
    HTTPT_RANGE_SET_IS_SATISFIABLE("bytes=5-10", 1, 0, false);
}

TEST(length) {
    struct http_range_set set, sset;

#define HTTPT_RANGE_SET_LENGTH_EQ(str_, entity_sz_, length_)             \
    do {                                                                 \
        if (http_range_set_parse(&set, str_) == -1)                      \
            TEST_ABORT("cannot parse range set: %s", http_get_error());  \
        http_range_set_simplify(&set, entity_sz_, &sset);                \
        TEST_UINT_EQ(http_range_set_length(&sset), length_);             \
        http_range_set_free(&set);                                       \
        http_range_set_free(&sset);                                      \
    } while (0)

    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-0", 20, 1);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-9", 20, 10);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-19", 20, 20);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-20", 20, 20);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-3,10-12", 20, 7);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-10,5-15", 20, 16);
    HTTPT_RANGE_SET_LENGTH_EQ("bytes=0-3,-10, -5", 20, 14);
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("ranges");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, simple_range);
    TEST_RUN(suite, no_first);
    TEST_RUN(suite, no_last);
    TEST_RUN(suite, multiple_ranges);
    TEST_RUN(suite, invalid);
    TEST_RUN(suite, simplify);
    TEST_RUN(suite, unsatisfiable);
    TEST_RUN(suite, length);

    test_suite_print_results_and_exit(suite);
}
