# Packaging script for the yescrypt library. Works on Python 2.6+ and 3.x.
import os
import re

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

HERE = os.path.dirname(os.path.abspath(__file__))


def read(name):
    with open(os.path.join(HERE, name)) as handle:
        return handle.read()


def get_version():
    init = read(os.path.join('yescrypt', '__init__.py'))
    match = re.search(r"__version__\s*=\s*'([^']+)'", init)
    if not match:
        raise RuntimeError('cannot find __version__ in yescrypt/__init__.py')
    return match.group(1)


setup(
    name='yescrypt',
    version=get_version(),
    author='github.com/arlsr',
    description='Pure-Python yescrypt password hashing',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    packages=['yescrypt'],
    python_requires='>=2.6, !=3.0.*, !=3.1.*, !=3.2.*',
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
)
