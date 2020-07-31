import ctypes
import ctypes.wintypes
import os
import struct
import threading

# https://msdn.microsoft.com/en-us/library/aa383751#DWORD_PTR
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong
PVOID = ctypes.wintypes.LPVOID
SIZE_T = ctypes.c_size_t

# 进程权限相关：https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020


def print_error(name):
    print(name, ctypes.WinError(ctypes.get_last_error()))


def float_to_hex(number):
    """
    将单浮点数转为16进制
    """
    return struct.unpack('<I', struct.pack('<f', number))[0]


def double_to_hex(number):
    """
    将双浮点数转为16进制
    """
    return struct.unpack('<Q', struct.pack('<d', number))[0]


def hex_to_float(hex_number):
    """
    将16进制转为单浮点数
    """
    return struct.unpack('<f', struct.pack('<I', hex_number))[0]


def hex_to_double(hex_number):
    """
    将16进制转为双浮点数
    """
    return struct.unpack('<d', struct.pack('<Q', hex_number))[0]


def get_process_info(pid):
    # https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-modules-for-a-process
    hProcess = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False, pid
    )
    if not hProcess:
        return

    count = 1  # 仅获取进程执行的文件
    hMods = (ctypes.c_ulong * count)()
    cbNeeded = ctypes.c_ulong()

    ctypes.windll.psapi.EnumProcessModules(
        hProcess,
        ctypes.byref(hMods),
        ctypes.sizeof(hMods),
        ctypes.byref(cbNeeded)
    )
    num = min(cbNeeded.value / ctypes.sizeof(ctypes.c_ulong), count)
    i = 0

    exe_name = ''
    while i < num:
        szModName = ctypes.c_buffer(100)
        # ret = ctypes.windll.psapi.GetModuleFileNameExA(
        # hProcess,
        # hMods[i],
        # szModName,
        # ctypes.sizeof(szModName)
        # )
        ret = ctypes.windll.psapi.GetModuleBaseNameA(
            hProcess,
            hMods[i],
            szModName,
            ctypes.sizeof(szModName)
        )
        if ret:
            print("%8d\t%s" % (pid, szModName.value))
            if i == 0:
                exe_name = szModName.value
        i += 1

    ctypes.windll.kernel32.CloseHandle(hProcess)
    return (pid, exe_name)


def list_process():
    # https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocesses
    count = 1024
    lpidProcess = (ctypes.c_ulong * count)()
    lpcbNeeded = ctypes.c_ulong()

    ret = ctypes.windll.psapi.EnumProcesses(
        ctypes.byref(lpidProcess),
        ctypes.sizeof(lpidProcess),
        ctypes.byref(lpcbNeeded)
    )

    if ret != 1:
        print_error('EnumProcesses')
        os._exit(1)

    num = min(lpcbNeeded.value / ctypes.sizeof(ctypes.c_ulong), count)
    i = 0

    result = {}
    while i < num:
        pid = lpidProcess[i]
        i += 1
        ret = get_process_info(pid)
        if ret and ret[1]:
            result[ret[1]] = ret[0]

    return result


def query_virtual(hProcess, base_addr):
    """
    查询虚拟地址的信息
    """
    MEM_COMMIT = 0x00001000
    PAGE_READWRITE = 0x04

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        """https://msdn.microsoft.com/en-us/library/aa366775"""
        _fields_ = (('BaseAddress', PVOID),
                    ('AllocationBase', PVOID),
                    ('AllocationProtect', ctypes.wintypes.DWORD),
                    ('RegionSize', SIZE_T),
                    ('State', ctypes.wintypes.DWORD),
                    ('Protect', ctypes.wintypes.DWORD),
                    ('Type', ctypes.wintypes.DWORD))

    mbi = MEMORY_BASIC_INFORMATION()
    ret = ctypes.windll.kernel32.VirtualQueryEx(
        hProcess,
        base_addr,
        ctypes.byref(mbi),
        ctypes.sizeof(mbi)
    )
    if not ret:
        print_error('VirtualQueryEx')
        return {}

    return {
        'protect': mbi.Protect == PAGE_READWRITE,
        'state': mbi.State == MEM_COMMIT,
        'size': mbi.RegionSize,
    }


def get_system_info():
    """
    获取系统信息: 可用内存的起始与结束地址
    """

    class SYSTEM_INFO(ctypes.Structure):
        """https://msdn.microsoft.com/en-us/library/ms724958"""

        class _U(ctypes.Union):
            class _S(ctypes.Structure):
                _fields_ = (('wProcessorArchitecture', ctypes.wintypes.WORD),
                            ('wReserved', ctypes.wintypes.WORD))

            _fields_ = (('dwOemId', ctypes.wintypes.DWORD),  # obsolete
                        ('_s', _S))
            _anonymous_ = ('_s',)

        _fields_ = (('_u', _U),
                    ('dwPageSize', ctypes.wintypes.DWORD),
                    ('lpMinimumApplicationAddress', ctypes.wintypes.LPVOID),
                    ('lpMaximumApplicationAddress', ctypes.wintypes.LPVOID),
                    ('dwActiveProcessorMask', DWORD_PTR),
                    ('dwNumberOfProcessors', ctypes.wintypes.DWORD),
                    ('dwProcessorType', ctypes.wintypes.DWORD),
                    ('dwAllocationGranularity', ctypes.wintypes.DWORD),
                    ('wProcessorLevel', ctypes.wintypes.WORD),
                    ('wProcessorRevision', ctypes.wintypes.WORD))
        _anonymous_ = ('_u',)

    sysinfo = SYSTEM_INFO()
    if not ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(sysinfo)):
        print_error('GetSystemInfo')
        return {}

    return {
        'start_addr': sysinfo.lpMinimumApplicationAddress,
        'end_addr': sysinfo.lpMaximumApplicationAddress
    }


def read_process(hProcess, base_addr, byte_num=2):
    """
    读取特定内存的值
    """
    if byte_num == 1:
        buf = ctypes.c_byte()
    elif byte_num == 2:
        buf = ctypes.c_short()
    elif byte_num == 4:
        buf = ctypes.c_int32()
    elif byte_num == 8:
        buf = ctypes.c_int64()
    else:
        buf = ctypes.c_buffer('', byte_num)

    nread = SIZE_T()
    ret = ctypes.windll.kernel32.ReadProcessMemory(
        hProcess,
        base_addr,
        ctypes.byref(buf),
        ctypes.sizeof(buf),
        ctypes.byref(nread)
    )
    if not ret:
        print_error('ReadProcessMemory')
        raise Exception('ReadProcessMemory')

    return getattr(buf, 'raw', buf.value)


def write_process(hProcess, base_addr, value, byte_num=2):
    """
    往特定内存地址写入数据
    """
    if byte_num == 1:
        buf = ctypes.c_byte(value)
    elif byte_num == 2:
        buf = ctypes.c_short(value)
    elif byte_num == 4:
        buf = ctypes.c_int32(value)
    else:
        buf = ctypes.c_int64(value)
    nwrite = SIZE_T()
    ret = ctypes.windll.kernel32.WriteProcessMemory(
        hProcess,
        base_addr,
        ctypes.byref(buf),
        ctypes.sizeof(buf),
        ctypes.byref(nwrite)
    )

    return not not ret


def close_process(hProcess):
    ctypes.windll.kernel32.CloseHandle(hProcess)


def inject_process(pid):
    """
    注入某个进程
    """
    hProcess = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        False, pid
    )
    if not hProcess:
        print_error('OpenProcess %s' % (pid))
        return

    return hProcess


"""
市场雇佣人数：  0x008E0F38  2Byte
市场第一项资源：0x008e0F4C  2Byte
市场标识： 0x008E0F38 值 0x00xx000000000005 后8Byte 值为 0x0000xx00000000xx 地址以 0x8 结尾
                                                人数
02  00  00  00  00  00  00  00  00  00  00  00  08  00  00  00
00  00  0C  00  05  00  00  00  00  4F  00  00  00  00  00  00
资源
D0  07  D1  07  D2  07  D3  07  D4  07  D5  07  D6  07  D7  07
06  00  00  00  00  00  00  00  00  00  00  00  05  00  00  00
00  00  02  00  00  00  00  00  00  5D  00  00  00  00  00  00
5C  05  08  07  A4  06  A4  06  A4  06  06  07  D1  06  17  07
房屋已住人口：   0x008DF616     0x008DF916      0x008DFA16      0x008DFE16
房屋还能住人口： 0x008DF618
房屋第一项资源： 0x008DF64A
                        已住人口
1B  00  00  00  00  00 |24  00||64  00| 23  00  24  00  00  00
00  00  00  00  00  00  00  00  00  00  00  00  00  01  00  00
00  00  00  00  00  00  00  00  00  00  FF  00  00  00  00  00
                                        资源1
00  00  00  00  00  18  00  00  00  00 |CD  00  00  00  00  00
00  00  00  00  00  00  00  00  00  00| 00  00  00  00  00  00
00  00  00  00  00  00  00  00  00  00  00  00  00  01  00  00
粮仓雇佣人数：  0x008E0EB8
粮仓可容纳量：  0x008E0ECC
粮仓第一项资源：0x008E0ECE  2Byte
粮仓标识： 0x008E0EB8 值 0x00xx000100010006 地址以 0x8 结尾
雇佣人数
06  00| 01  00  01  00  03  00  00  00  00  00  00  00  00  00
                可容纳量 谷     蔬菜    水果
00  00  00  00  58  1B||00  00  00  00  00  00  00  00  00  00
鱼
00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00
"""

ALL_MARKET_ADDRESSES = []
ALL_GRANARY_ADDRESSES = []
TIMER_INTERVAL = 5

CITY_MONEY_ADDRESS = 0x00505160  # 城市的金钱
PERSON_MONEY_ADDRESS = 0x00509424  # 个人的金钱
RATING_ITEMS = [0x005092DC, 0x005092E0, 0x005092E4, 0x005092E8]  # 四项评比指标： 文化，繁荣，和平，支持度

TIMER = None


def list_market_and_granary(hProcess, sysinfo):
    """
    查找所有的市场与粮仓
    """
    # current_address = sysinfo['start_addr']
    # end_address = sysinfo['end_addr']
    current_address = 0x008d0008
    end_address = 0x009FFFFF

    result = {'market': [], 'granary': []}

    debug_addrs = []
    while current_address < end_address:
        addr = current_address
        mem_info = query_virtual(hProcess, addr)
        if mem_info['protect'] and mem_info['state']:
            try:
                value = read_process(hProcess, addr, 8)
            except Exception:
                continue

            if addr in debug_addrs:
                print('-----------debug', hex(addr), hex(value))
            if (value & 0xff00ffffffffffff) == 0x0000000100010006:  # 雇佣6人的粮仓
                total_volume = read_process(hProcess, addr + 0x14, 2)
                value_num = 8
                i = 0
                values = []
                while i < value_num:
                    values.append(read_process(hProcess, addr + 0x16 + 2 * i, 2))
                    i += 1
                if (sum(values) + total_volume) == 2400:  # 粮仓总容量为 2400
                    result['granary'].append(addr)
            elif (value & 0xff00ffffffffffff) == 0x0000000000000005:  # 雇佣5人的市场
                try:
                    next_value = read_process(hProcess, addr + 8, 8)
                except Exception:
                    continue
                if (next_value & 0xffff000000000000) == 0 and (next_value & 0x0000ff0000000000) != 0:
                    # 最高2个字节为0；再下一个字节不为0
                    print
                    hex(addr), hex(value)
                    result['market'].append(addr)

        current_address += 0x10

    global ALL_MARKET_ADDRESSES
    global ALL_GRANARY_ADDRESSES
    ALL_MARKET_ADDRESSES = result['market']
    ALL_GRANARY_ADDRESSES = result['granary']
    ALL_MARKET_ADDRESSES.sort()
    ALL_GRANARY_ADDRESSES.sort()

    print(u'所有市场：', map(lambda x: hex(x), ALL_MARKET_ADDRESSES))
    print(u'所有粮仓：', map(lambda x: hex(x), ALL_GRANARY_ADDRESSES))

    return result


def update_market(hProcess, base_addr, sysinfo):
    """
    修改市场8项资源
    """
    i = 0

    mem_info = query_virtual(hProcess, base_addr)
    if not mem_info:
        os._exit(1)

    while i < 8:
        addr = base_addr + (i * 2)
        if addr < sysinfo['start_addr'] or addr >= sysinfo['end_addr']:
            print(hex(addr), u'超出内存范围')
            return

        if mem_info['protect'] and mem_info['state']:
            write_process(hProcess, addr, 9000 + i, 2)

        i += 1


def update_granary(hProcess, base_addr, sysinfo):
    """
    修改粮仓4项资源
    """
    addr = base_addr
    if addr < sysinfo['start_addr'] or addr >= sysinfo['end_addr']:
        print(hex(addr), u'超出内存范围')
        return

    mem_info = query_virtual(hProcess, addr)
    if not mem_info:
        os._exit(1)
    write_process(hProcess, addr + 0, 50, 2)
    # cheat_engine.write_process(hProcess, addr+2, 50, 2)
    # cheat_engine.write_process(hProcess, addr+4, 50, 2)
    # cheat_engine.write_process(hProcess, addr+10, 50, 2)


def update_money(hProcess, sysinfo):
    """
    个人金钱加5000
    """
    addr = PERSON_MONEY_ADDRESS
    mem_info = query_virtual(hProcess, addr)
    if not mem_info:
        os._exit(1)

    try:
        value = read_process(hProcess, addr, 4)
    except Exception:
        return
    value += 5000
    write_process(hProcess, addr, value, 4)


def update_indicator(hProcess, sysinfo):
    """
    四项评比指标全加10
    """
    addr = RATING_ITEMS[0]
    mem_info = query_virtual(hProcess, addr)
    if not mem_info:
        os._exit(1)

    for addr in RATING_ITEMS:
        try:
            value = read_process(hProcess, addr, 2)
        except Exception:
            continue
        value += 10
        if value > 100:
            value = 100
        write_process(hProcess, addr, value, 2)


def freeze_mem(hProcess, info):
    """
    锁定内存：定时修改内存的值
    """
    # print 'freeze_mem......'
    for addr in ALL_MARKET_ADDRESSES:
        update_market(hProcess, addr + 0x14, info)

    # for addr in ALL_GRANARY_ADDRESSES:
    # update_granary(hProcess, addr+0x16, info)

    TIMER = threading.Timer(TIMER_INTERVAL, freeze_mem, [hProcess, info])
    TIMER.start()


def print_help():
    print(u'c - 清除扫描结果')
    print(u'p - 个人金钱加5000')
    print(u's - 查找所有的市场与粮仓内存')
    print(u'u - 四项评比指标全加10')
    print(u'q - 退出')
    print(u'h - 查看该帮助')


def main():
    # 获取凯撒大帝3的游戏进程
    processes = list_process()
    pid = processes.get('c3.exe')

    if not pid:
        print(u'游戏没有启动', os._exit(1))

    info = get_system_info()
    if not info:
        return

    print(u'当前游戏进程：', pid)

    hProcess = inject_process(pid)
    if not hProcess:
        return

    TIMER = threading.Timer(TIMER_INTERVAL, freeze_mem, [hProcess, info])
    TIMER.start()

    global ALL_MARKET_ADDRESSES
    global ALL_GRANARY_ADDRESSES

    print_help()
    while True:
        print(u'请输入指令：')
        op = 'p'
        if op == 'q':
            close_process(hProcess)
            os._exit(1)
        elif op == 'h':
            print_help()
        elif op == 'c':
            ALL_MARKET_ADDRESSES = []
            ALL_GRANARY_ADDRESSES = []
        elif op == 'p':
            update_money(hProcess, info)
        elif op == 'u':
            update_indicator(hProcess, info)
        elif op == 's':
            list_market_and_granary(hProcess, info)

    close_process(hProcess)


if __name__ == '__main__':
    # main()
    list_process()
