.. include:: references.rst
.. _startguide:

************
Installation
************

Requirements
============

Jetconf requires **Python 3.5** or **newer**::

    $ apt-get install python3
    $ apt-get install python3-pip


Other requirements should be installed automatically during installation.

Stable version - PyPI
=====================

Stable version is the most actual package version provided by Python Package Index (PyPI)::

    $ pip install jetconf

Latest version - GitHub
=======================

Latest version is the most actual source code available in the Jetconf GitHub repository. It is the ``master`` branch.

To install Jetconf from source::

    $ git clone https://github.com/CZ-NIC/jetconf.git
    $ cd jetconf
    $ pip install -r requirements.txt
    $ python3 setup.py install

******************************
Sample jukebox-jetconf backend
******************************

``jukebox-jetconf`` is an sample backend project created for Jetconf.
It is very useful as template for start developing a new Jetconf backend.

Installation
============

Clone backend project from repository::

    $ git clone https://github.com/CZ-NIC/jukebox-jetconf

Install backend package::

    $ cd jukebox-jetconf
    $ pip install .

Now the backend package should be installed.

Configuration
=============

In the ``data`` directory of Jetconf_ repository there are some example files.

- ``jetconf@.service``: simple systemd integration for Jetconf
- ``example-config.yaml``: configuration file configured to working with *jukebox* backend and other files in *data* directory
- ``doc-root``:  default root directory for Jetconf HTTP server
- ``ca.pem``: example generated self-signed Certification Authority certificate

**server certificate**:

    - ``server_localhost.crt`` : example generated Jetconf server certificate
    - ``server_localhost.key``: key for *server_localhost.crt* certificate

**client certificates**:

    - ``example-client.pem``: basic client certificate
    - ``example-client_curl.pem``: client certificate for usage with cURL
    - ``example-client_browser.pfx``: client certificate in PKCS #12 format for usage with browser
    - ``pfx_passwd``: password for *example-client_browser.pfx* certificate

.. warning::

    Certificates provided with Jetconf are only generated to test or try Jetconf.
    Never use these certificates in final application.

Easiest way to run Jetconf with jukebox backend is to clone full Jetconf repository and start working in ``data`` directory::

    $ git clone https://github.com/CZ-NIC/jetconf.git
    $ cd jetconf/data

Paths in ``example-config.conf`` must be updated.
If backend is installed and paths in configuration file are configured, Jetconf can be run.

Set up all on your own:

* :ref:`configuration`
* :ref:`certificates`

***********
Run Jetconf
***********

command line
============
All logging information will be displayed in terminal::

    $ jetconf -c <path_to_config_file.yaml>



systemd
=======

In ``data`` directory there is a simple ``systemd`` service file for Jetconf.
To allow running Jetconf using systemd, this file needs to be copied to ``/etc/systemd/system/``::

    $ cp jetconf@.service /etc/systemd/system/

Change the user in ``/etc/systemd/system/jetconf@.service`` to yours or create ``jetconf`` user.

Move ``.yaml`` config file to ``/etc/jetconf``. It must be named like ``config-backend_name.yaml``.
For example, configuration file for *jukebox* backend will be ``config-jukebox.yaml``.
It is nice to use Jetconf backend's name without *jetconf* suffix.

::

    $ cp example-config.yaml /etc/jetconf/config-jukebox.yaml

Last, Jetconf service can be started in format ``jetconf@backend_name.service``.
For ``jukebox`` backend from above::

    $ systemctl start jetconf@jukebox.service



