from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))
with codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8') as readme:
    long_description = readme.read()

setup(
    name="jetconf",
    packages=find_packages(),
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    description="Pure Python implementation of the RESTCONF protocol",
    long_description=long_description,
    url="https://github.com/CZ-NIC/jetconf",
    author="Ales Mrazek",
    author_email="ales.mrazek@nic.cz",
    entry_points={
        "console_scripts": ["jetconf=jetconf.__main__:main"]
    },
    install_requires=["yangson", "h2", "colorlog", "pyaml", "pytz"],
    tests_require=["pytest"],
    keywords=["restconf", "yang", "data model", "configuration", "json"],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration"
    ]
)
