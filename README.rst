*******
Jetconf
*******

Jetconf is an implementation of the RESTCONF_ protocol written in
Python 3.

* `Documentation`_
* `Git repository`_

Main features:

* HTTP/2 over TLS, certificate-based authentication of clients

* JSON data encoding

* Per-user candidate datastores with transactions

* Support for NACM_

Installation
============
Python 3.5 or newer is required::

    ~$ apt-get install python3
    ~$ apt-get install python3-pip

Jetconf can be installed by PyPI::

   $ python3 -m pip install jetconf

Run Jetconf
===========
::

    ~$ jetconf -c <path_to_config_file.yaml>

.. _RESTCONF: https://tools.ietf.org/html/draft-ietf-netconf-restconf-18
.. _NACM: https://datatracker.ietf.org/doc/rfc6536/
.. _Git repository: https://github.com/CZ-NIC/jetconf
.. _Documentation: https://jetconf.readthedocs.io
