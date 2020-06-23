import feedparser

url = 'https://rsshub.app/weibo/search/hot'
url = 'https://www.oschina.net/news/rss'
data = feedparser.parse(url)

print(data)
# 标题
print(data['feed'].title)
print(data.feed.title)
# rss源链接
print(data.feed.link)
# 子标题
print(data.feed.subtitle)
