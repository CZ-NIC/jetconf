.. |date| date::

*******
JetConf
*******

:Author: Pavel Špírek <pavel.spirek@nic.cz>
:Date: |date|

*JetConf* is an implementation of the RESTCONF_ protocol written in
Python 3. Main features:

* HTTP/2 over TLS, certificate-based authentication of clients

* JSON data encoding

* Per-user candidate datastores with transactions

* Support for NACM_

Requirements
=============

*JetConf* requires Python 3.6 or newer::

    $ sudo apt-get install python3
    $ sudo apt-get install python3-pip


These requirements should be installed by running *Instalation*

::

    colorlog
    h2==3.0.1
    pytz
    PyYAML
    yangson
    


Installation
============

*JetConf* can be installed by PyPI:

::

   $ python3 -m pip install jetconf


Running
=======

Running *JetConf*

::

    $ jetconf -c <path_to_config_file.yaml>

For development purposes, *JetConf* can also be started directly
from Git repository with run.py script:

::

    $ ./run.py -c <path_to_config_file.yaml>
    

Example configuration (template)
================================

In the 'data' folder, there is an example template for
configuring paths, certificates etc.

::

    example-config.yaml
    


In this configuration file, you have to modify all paths to match
your actual file locations.


Links
=====
* `Git repository`_
* `Documentation`_

.. _RESTCONF: https://tools.ietf.org/html/draft-ietf-netconf-restconf-18
.. _NACM: https://datatracker.ietf.org/doc/rfc6536/
.. _Git repository: https://github.com/CZ-NIC/jetconf
.. _Documentation: https://gitlab.labs.nic.cz/labs/jetconf/wikis/home
