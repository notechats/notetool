# 导入SQLite驱动：
from notetool.download.m3u8 import m3u8Dataset

m3u8 = m3u8Dataset(db_path='/Users/liangtaoniu/workspace/MyDiary/tmp/tmpfile/m3u8-list.db')

print(m3u8.select())
