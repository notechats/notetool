import os

import psutil

pids = psutil.pids()

for pid in pids:
    p = psutil.Process(pid)
    print("pid-%d,pname-%s" % (pid, p.name()))
    p.cpu_num()
os.popen()
