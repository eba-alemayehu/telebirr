
from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.1.1'
DESCRIPTION = 'Telebirr integration'
LONG_DESCRIPTION = 'This package is a helper package with telebirr integration.'

# Setting up
setup(
    name="telebirr",
    version=VERSION,
    author="Eba Alemayehu",
    author_email="<ebaalemayhu3@gmail.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=['pycryptodome', 'requests', 'cryptography'],
    keywords=['python', 'telebirr', 'payment', 'ethiopia', 'ethio telecom'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)