from notetool.download import MultiThreadDownload

downer = MultiThreadDownload()
downer.download('http://www.cjcp.org.cn/CN/article/downloadArticleFile.do?attachType=PDF&id=95',
                'tmp/a.pdf',
                overwrite=True)
