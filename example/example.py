from notework.youzan.items import get_data_from_dp, get_item_detail, get_day

res = get_item_detail(item_id="466973942", shop_id="1206788")

print(res)

day1 = get_day()
print(day1)

df = get_data_from_dp()
print(df.dtypes)
