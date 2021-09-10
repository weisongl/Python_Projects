a = [[1,4],[4,5]]
a = [[1, 3], [2, 6], [8, 10], [15, 18]]
set([[1,4],[1,4]])
a = [[1, 3],[1,2] ,[2, 6], [15, 18],[8, 10] ]
sorted(a)
# https://leetcode.com/problems/merge-intervals/submissions/

def merge(self, intervals):
    intervals.sort(key=lambda x: x[0])

    merged = []
    for interval in intervals:
        # if the list of merged intervals is empty or if the current
        # interval does not overlap with the previous, simply append it.
        if not merged or merged[-1][1] < interval[0]:
            merged.append(interval)
        else:
            # otherwise, there is overlap, so we merge the current and previous
            # intervals.
            merged[-1][1] = max(merged[-1][1], interval[1])

    return merged
