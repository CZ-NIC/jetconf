from setuptools import setup
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))
with codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8') as readme:
    long_description = readme.read()

setup(
    name = "jetconf",
    packages = ["jetconf"],
    version = "0.1.0",
    description = "RESTCONF over HTTP/2",
    long_description = long_description,
    url = "https://gitlab.labs.nic.cz/labs/jetconf",
    author = "Pavel Špírek",
    author_email = "pavel.spirek@nic.cz",
    license = "GPLv3",
    install_requires = ["yangson"],
    tests_require = ["pytest"],
    keywords = ["RESTCONF", "configuration", "json"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration"]
    )
