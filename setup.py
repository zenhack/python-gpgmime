from setuptools import setup
from os.path import join, dirname


def _get_readme():
    with open(join(dirname(__file__), 'README.md')) as f:
        return f.read()


setup(name='gpgmime',
      version='0.1',
      packages=['gpgmime'],
      install_requires=['python-gnupg'],
      author='Ian Denhardt',
      author_email='ian@zenhack.net',
      description='Library for manipulating PGP-Mime email.',
      long_description=_get_readme(),
      license='GPLv3+',
      url='https://github.com/zenhack/python-pgpmime',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
      ])
