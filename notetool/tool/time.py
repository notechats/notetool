import time


def now2unix():
    """
    当前时间戳
    :return:
    """
    return int(time.mktime(time.localtime()))


def now2time(time_type='%Y-%m-%d %H:%M:%S'):
    """
    当前时间
    :return:
    """
    return time.strftime(time_type, time.localtime())


def time2unix(time_str, time_type='%Y-%m-%d %H:%M:%S'):
    """
    > str2unix('2013-10-10 23:40:00')

    '2013-10-10 23:40:00'
    :param time_str:
    :param time_type: '%Y-%m-%d %H:%M:%S'
    :return:
    """
    return int(time.mktime(time.strptime(time_str, time_type)))


def unix2time(time_stamp, time_type='%Y-%m-%d %H:%M:%S'):
    return time.strftime(time_type, time.localtime(time_stamp))


def example():
    print(now2unix())
    print(now2time())
    print(time2unix(now2time()))
    print(unix2time(now2unix()))
