import sys

from setuptools import setup, find_packages


def get_version(argv):
    if len(argv) <= 1:
        return
    if argv[1] != 'build':
        return
    from os import path
    here = path.abspath(path.dirname(__file__))
    version_path = path.join(here, '__version__.md')
    if path.exists(version_path):
        with open(version_path, 'r') as f:
            version1 = [int(i) for i in f.read().split('.')]
    else:
        version1 = [0, 0, 1]
    version2 = version1[0] * 100 + version1[1] * 10 + version1[2] + 1

    version1[2] = version2 % 10
    version1[1] = int(version2 / 10) % 10
    version1[0] = int(version2 / 100)
    version3 = '{}.{}.{}'.format(*version1)
    with open(version_path, 'w') as f:
        f.write(version3)
    return version3


version = get_version(sys.argv)

install_requires = ['IPython', 'matplotlib', 'pycurl', 'cryptography', 'six']

setup(name='notetool',
      version=version,
      description='notetool',
      author='niuliangtao',
      author_email='1007530194@qq.com',
      url='https://github.com/1007530194',

      packages=find_packages(),
      install_requires=install_requires
      )
