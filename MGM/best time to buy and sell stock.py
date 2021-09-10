
def maxProfit(prices) -> int:
    output = 0
    a = prices
    n = len(prices)
    i=0
    for i in range(n-1):
        output = max(output,max(a[i+1:])-a[i])
    return output

prices = [7,1,5,3,6,4]
maxProfit(prices)

class Solution:
    def maxProfit(prices) :
        min_price = prices[0]
        max_profit = 0
        for price in prices:
            max_profit = max(price - min_price,max_profit)
            min_price = min(price,min_price)
        return max_profit