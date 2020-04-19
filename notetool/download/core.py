import concurrent.futures
import os
from threading import Lock

import pycurl
import requests
from requests import get

from notetool.tool import exists_file, delete_file, path_parse
from notetool.tool import log

logger = log(__name__)

__all__ = ['BaseDownLoad', 'MultiThreadDownload', 'PyCurlDownLoad', 'download']


def info(msg):
    logger.info(msg)


class BaseDownLoad:
    def __init__(self, url, path, overwrite=False):
        self.url = url
        self.path = path_parse(path)
        self.overwrite = overwrite
        self.size = None

    def download(self):
        if exists_file(file_path=self.path, mkdir=True):
            if self.overwrite:
                delete_file(file_path=self.path)
            else:
                info('file exist and return[path={}].'.format(self.path))
                return
        file_name = os.path.basename(self.path)
        info("download {} from {} to {} ".format(file_name, self.url, self.path))
        self._download()
        info('download {} success'.format(file_name))

    def _download(self):
        pass


class MultiThreadDownload(BaseDownLoad):
    def __init__(self, url, path, nums=5, overwrite=False):
        super(MultiThreadDownload, self).__init__(url=url, path=path, overwrite=overwrite)
        self.lock = Lock()
        self.num = nums

    def down(self, start, end):
        headers = {'Range': 'bytes={}-{}'.format(start, end)}
        # stream = True 下载的数据不会保存在内存中
        r = get(self.url, headers=headers, stream=True)
        # 写入文件对应位置,加入文件锁
        self.lock.acquire()
        with open(self.path, "rb+") as fp:
            fp.seek(start)
            fp.write(r.content)
            self.lock.release()
            # 释放锁

    def _download(self, **kwargs):
        r = requests.head(self.url)
        # 若资源显示302,则迭代找寻源文件
        while r.status_code == 302:
            self.url = r.headers['Location']
            logger.warning("该url已重定向至{}".format(self.url))
            r = requests.head(self.url)
        self.size = int(r.headers['Content-Length'])
        info('该文件大小为：{} bytes'.format(self.size))

        # 创建一个和要下载文件一样大小的文件
        fp = open(self.path, "wb")
        fp.truncate(self.size)
        fp.close()
        # 启动多线程写文件
        part = self.size // self.num
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.num)
        futures = []
        for i in range(self.num):
            start = part * i
            # 最后一块
            if i == self.num - 1:
                end = self.size
            else:
                end = start + part - 1
                info('{}->{}'.format(start, end))
            futures.append(pool.submit(self.down, start, end))
        concurrent.futures.wait(futures)


class PyCurlDownLoad(BaseDownLoad):
    def __init__(self, url, path, overwrite=False):
        super(PyCurlDownLoad, self).__init__(url, path, overwrite)

    def _download(self):
        with open(self.path, 'wb') as f:
            c = pycurl.Curl()
            c.setopt(pycurl.URL, self.url)
            c.setopt(pycurl.WRITEDATA, f)
            c.perform()
            c.close()


def download(url, path, overwrite=False, mode='curl'):
    if mode == 'curl':
        down = PyCurlDownLoad(url, path, overwrite=overwrite)
    else:
        down = MultiThreadDownload(url, path, overwrite=overwrite)
    down.download()
