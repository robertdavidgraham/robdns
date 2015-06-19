#ifndef RANGES_H
#define RANGES_H
#include <stdint.h>

typedef uint64_t IPV6ADDR;

/**
 * A range of either IP addresses or ports
 */
struct Range
{
    unsigned begin;
    unsigned end; /* inclusive */
};
struct RangeV6
{
    uint64_t begin[2];
    uint64_t end[2];
};

struct RangeList
{
    struct Range *list;
    unsigned count;
    unsigned max;
};

struct RangeListV6
{
    struct Range6 *list;
    unsigned count;
    unsigned max;
};

/**
 * Adds the given range to the task list. The given range can be a duplicate
 * or overlap with an existing range, which will get combined with existing
 * ranges. 
 * @param task
 *      A list of ranges of either IPv4 addresses or port numbers.
 * @param begin
 *      The first address of the range that'll be added.
 * @param end
 *      The last address (inclusive) of the range that'll be added.
 */
void
rangelist_add_range(struct RangeList *task, unsigned begin, unsigned end);
void
rangelist_add_range_v6(struct RangeList *task, uint64_t begin[2], uint64_t end[2]);

/**
 * Removes the given range from the target list. The input range doesn't
 * have to exist, or can partial overlap with existing ranges.
 * @param task
 *      A list of ranges of either IPv4 addresses or port numbers.
 * @param begin
 *      The first address of the range that'll be removed.
 * @param end
 *      The last address of the range that'll be removed (inclusive).
 */
void
rangelist_remove_range(struct RangeList *task, unsigned begin, unsigned end);
void
rangelist_remove_range_v6(struct RangeList *task, uint64_t begin[2], uint64_t end[2]);

/**
 * Same as 'rangelist_remove_range()', except the input is a range
 * structure instead of a start/stop numbers.
 */
void
rangelist_remove_range2(struct RangeList *task, struct Range range);

/**
 * Returns 'true' is the indicated port or IP address is in one of the task
 * ranges.
 * @param task
 *      A list of ranges of either IPv4 addresses or port numbers.
 * @param number
 *      Either an IPv4 address or a TCP/UDP port number.
 * @return 
 *      'true' if the ranges contain the item, or 'false' otherwise
 */
int
rangelist_is_contains(const struct RangeList *task, unsigned number);
int
rangelist_is_contains_v6(const struct RangeList *task, uint64_t number[2]);


/**
 * Remove things from the target list. The primary use of this is the
 * "exclude-file" containing a list of IP addresses that we should
 * not scan
 * @param targets
 *      Our array of target IP address (or port) ranges that we'll be
 *      scanning.
 * @param excludes
 *      A list, probably read in from --excludefile, of things that we
 *      should not be scanning, that will override anything we otherwise
 *      try to scan.
 * @return
 *      the total number of IP addresses or ports removed.
 */
uint64_t
rangelist_exclude(  struct RangeList *targets,
              const struct RangeList *excludes);

uint64_t
rangelist_exclude_v6(  struct RangeListV6 *targets,
              const struct RangeListV6 *excludes);


/**
 * Counts the total number of IP addresses or ports in the target list. This
 * iterates over all the ranges in the table, summing up the count within
 * each range.
 * @param targets
 *      A list of IP address or port ranges.
 * @return
 *      The total number of address or ports.
 */
uint64_t
rangelist_count(const struct RangeList *targets);

uint64_t
rangelist_count_v6(const struct RangeListV6 *targets);

/**
 * Given an index in a continous range of [0...count], pick a corresponding
 * number (IP address or port) from a list of non-continuous ranges (not
 * necessarily starting from 0). In other words, given the two ranges
 *    10-19 50-69
 * we'll have a total of 30 possible numbers. Thus, the index goes from
 * [0..29], with the values 0..9 picking the corresponding values from the
 * first range, and the values 10..29 picking the corresponding values
 * from the second range.
 *
 * NOTE: This is a fundamental part of this program's design, that the user
 * can specify non-contiguous IP and port ranges, but yet we iterate over
 * them using a monotonicly increasing index variable.
 *
 * @param targets
 *      A list of IP address ranges, or a list of port ranges (one or the
 *      other, but not both).
 * @param index
 *      An integer starting at 0 up to (but not including) the value returned
 *      by 'rangelist_count()' for this target list.
 * @return
 *      an IP address or port corresponding to this index.
 */
unsigned rangelist_pick(const struct RangeList *targets, uint64_t i);
IPV6ADDR rangelist_pick_v6(const struct RangeListV6 *targets, uint64_t i);




/**
 * Remove all the ranges in the range list.
 */
void
rangelist_remove_all(struct RangeList *list);
void
rangelist_remove_all_v6(struct RangeList *list);



/**
 * Does a regression test of this module
 * @return
 *      0 if the regression test succeeds, or a positive value on failure
 */
int
ranges_selftest(void);


#endif
