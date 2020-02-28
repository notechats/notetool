from notetool.download.m3u8 import m3u8Dataset
from notetool.download.m3u8 import m3u8Downloader
from notetool.download.parse_m3u8 import parse_url_pages
from notetool.tool import set_secret_path

set_secret_path('/Users/liangtaoniu/workspace/MyDiary/tmp/tmpfile/m3u8-key')
db_path = '/Users/liangtaoniu/workspace/MyDiary/tmp/tmpfile/m3u8-list.db'


def test1():
    parse_url_pages(pages=range(13, 50), save_path=db_path)


def test2():
    dir_list = '/Users/liangtaoniu/Downloads/crack'
    downloader = m3u8Downloader()

    m3u8 = m3u8Dataset(db_path=db_path)

    for url in m3u8.select(100):
        try:
            print(url)
            downloader.start(url[0], dir_list, url[1])
            m3u8.update(url=url[0])
        except Exception as e:
            print(e)


test1()
# test2()
