from setuptools import setup

setup(name='pgpmime',
      version='0.1',
      packages=['pgpmime'],
      install_requires=['pygpgme'],
      author='Ian Denhardt',
      author_email='ian@zenhack.net',
      description='Library for manipulating PGP-Mime email.',
      license='GPL-3.0',
      url='https://github.com/zenhack/python-pgpmime',
      )