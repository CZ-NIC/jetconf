*******
Jetconf
*******

Jetconf is an implementation of the RESTCONF_ protocol written in
Python 3.

* `Documentation`_
* `GitHub repository`_

Main features:

* HTTP/2 over TLS, certificate-based authentication of clients

* JSON data encoding

* Per-user candidate datastores with transactions

* Support for NACM_

Requirements
============

Jetconf requires **Python 3.6 or newer**::

    ~$ apt-get install python3
    ~$ apt-get install python3-pip


These requirements should be installed by running *Instalation*

::

    colorlog
    h2==3.0.1
    pytz
    PyYAML
    yangson


Installation
============

JetConf can be installed by PyPI::

   $ python3 -m pip install jetconf


Running
=======

Running JetConf::

    ~$ jetconf -c <path_to_config_file.yaml>

For development purposes, JetConf can also be started directly
from git repository with ``run.py`` script.::

    ~$ ./run.py -c <path_to_config_file.yaml>


Example configuration (template)
================================

In the ``data`` folder, there is an example template ``example-config.yaml`` for
configuring paths, certificates etc.


In this configuration file, you have to modify all paths to match
your actual file locations.


.. _RESTCONF: https://tools.ietf.org/html/draft-ietf-netconf-restconf-18
.. _NACM: https://datatracker.ietf.org/doc/rfc6536/
.. _GitHub repository: https://github.com/CZ-NIC/jetconf
.. _Documentation: https://jetconf.readthedocs.io
