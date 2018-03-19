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

Prerequisites
=============

*JetConf* requires Python 3.5 ::

    $ sudo apt-get install python3
    $ sudo apt-get install python3-pip


These requirements should be installed by running *Instalation*

::

    colorlog==2.10.0
    h2==3.0.1
    hpack==2.3.0
    hyperframe==5.0.0
    pyaml==16.12.2
    pytz==2016.10
    PyXB==1.2.5
    PyYAML==3.12
    yangson==1.3.16
    


Installation
============

::

   $ python3 -m pip install jetconf


Note that *JetConf* requires Python 3.5.

Running
============

Running JetConf

::

    $ cd jetconf
    $ ./run.py -c <path_to_config_file.yaml>
    


Example configuration (template)
============

In folder 'data' is example template for configuring paths, certificates etc.

example config file

::

    example-config.yaml
    


In this configuration file you have to setup paths.


Links
=====
* `Git repository`_
* `Documentation`_

.. _RESTCONF: https://tools.ietf.org/html/draft-ietf-netconf-restconf-18
.. _NACM: https://datatracker.ietf.org/doc/rfc6536/
.. _Git repository: https://github.com/CZ-NIC/jetconf
.. _Documentation: https://gitlab.labs.nic.cz/labs/jetconf/wikis/home
