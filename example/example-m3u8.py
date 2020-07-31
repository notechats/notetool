from notetool.download.m3u8 import m3u8Dataset
from notetool.download.m3u8 import m3u8Downloader

from notetool.tool import set_secret_path

set_secret_path('/Users/liangtaoniu/workspace/MyDiary/tmp/tmpfile/m3u8-key')
db_path = '/Users/liangtaoniu/workspace/MyDiary/tmp/tmpfile/m3u8-list.db'


def example2():
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


# test2()
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept': 'video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Range': 'bytes=0-',
    'Connection': 'keep-alive',
    'Referer': 'https://appukvkryx45804.h5.xiaoeknow.com/content_page/eyJ0eXBlIjoxMiwicmVzb3VyY2VfdHlwZSI6NCwicmVzb3VyY2VfaWQiOiJsXzVmMTAwZmZlZTRiMDQzNDk4OTZjNTRiOSIsInByb2R1Y3RfaWQiOiIiLCJhcHBfaWQiOiJhcHB1a1ZrUll4NDU4MDQiLCJleHRyYV9kYXRhIjowfQ?entry=3&entry_type=0&pro_id=p_5f0ef17de4b0ee0b88729cc4',
}

params = (
    ('time', '1595843697088'),
)

response = requests.get(
    'https://1252524126.vod2.myqcloud.com/9764a7a5vodtransgzp1252524126/5d4fc7d35285890805676406366/drm/v.f230.m3u8',
    headers=headers, params=params)


def download():
    url = 'https://1252524126.vod2.myqcloud.com/9764a7a5vodtransgzp1252524126/5d4fc7d35285890805676406366/drm/v.f230.m3u8'
    # url = "https://1252524126.vod2.myqcloud.com/9764a7a5vodtransgzp1252524126/5d4fc7d35285890805676406366/drm/v.f230.ts?start=0&end=1190607&type=mpegts&time=1595843697088"
    downloader = m3u8Downloader()
    downloader.start(url, '/Users/liangtaoniu/workspace/MyDiary/notechats/notetool/example/tmp', 'test.mp4')


#
download()
