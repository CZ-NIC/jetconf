.. include:: references.rst
.. _configuration:

*********************
Configuration options
*********************

.. contents::
   :depth: 2
   :local:

Jetconf configuration is set as ``.conf`` text file in YAML format loaded by Jetconf on startup.
Jetconf configuration has two types sections, *common* sections and *application-specific* sections.


Common sections
===============

Common sections are configuring core Jetconf settings available in any running same version of Jetconf.
It do not depend on the Jeconf backend package.

GLOBAL:
-------

Example
^^^^^^^

.. code-block:: yaml

    GLOBAL:
        TIMEZONE: "Europe/Prague"
        LOGFILE: "-"
        PIDFILE: "/tmp/jetconf.pid"
        PERSISTENT_CHANGES: true
        LOG_LEVEL: "info"
        LOG_DBG_MODULES: ["usr_conf_data_handlers", "data"]
        YANG_LIB_DIR: "yang-data/"
        DATA_JSON_FILE: "data.json"
        VALIDATE_TRANSACTIONS: true
        CLIENT_CN: false
        BACKEND_PACKAGE: "jetconf_jukebox"

Options
^^^^^^^

.. code-block:: yaml

    TIMEZONE:

*Default:* ``"GMT"``

A timezone of the Jetconf server.
This is necessary because all timestamps returned in HTTP response headers need to be returned in GMT.

.. code-block:: yaml

    LOGFILE:

*Default:* ``"-"``

A location of Jetconf's log file. This can be either a ``path`` on the filesystem or a ``-``.
If configured as a ``-``, Jetconf server will run in foreground and all logging information will
be written to stdout (suitable for testing).

.. code-block:: yaml

    PIDFILE:

*Default:* ``"/tmp/jetconf.pid"``

A location of Jetconf's process ID file.

.. code-block:: yaml

    PERSISTENT_CHANGES:

*Default:* ``true``

This option specifies if the changes commited to datastore will also be synchronized to the filesystem
(*JSON* file defined by the ``DATA_JSON_FILE`` option). It should be set to true in most cases, but can be turned
off for i.e. testing purposes. If turned off, the Jetconf datastore will contain exactly the same initial
data at every startup.

.. code-block:: yaml

    LOG_LEVEL:

*Default:* ``"info"``

Defines the Jetconf's log verbosity. Possible values are: ``debug``, ``info``, ``warning`` and ``error``.

.. code-block:: yaml

    LOG_DBG_MODULES:

*Default:* ``[*]``

When ``LOG_LEVEL`` is set to "debug", this options defines list of Python modules which will write out debugging information.
This is useful to prevent flooding the log with debugging messages from irrelevant modules.
I.e. when debugging ``"usr_conf_data_handlers"`` module, you may not be interested with debug
information from the ``"nacm"``. Can be set to wildcard ``*``.

.. code-block:: yaml

    YANG_LIB_DIR:

*Default:* ``"yang-data/"``

Specifies the location of **YANG library**. This is the directory containing ``*.yang`` files,
it must also contain the ``"yang-library-data.json"`` file with configuration and description of
all present YANG modules.

.. code-block:: yaml

    DATA_JSON_FILE:

*Default:* ``"data.json"``

A path to JSON file containing the datastore data. This file will be loaded at Jetconf startup.
If ``PERSISTENT_CHANGES`` option is set to true, all changes made to the datastore will be also stored
to this file.

.. code-block:: yaml

    VALIDATE_TRANSACTIONS:

*Default:* ``true``

This option defines if the datastore data should be validated according to
YANG data model after a transaction is commited. It should be set to true except for
testing and debugging purposes.

.. code-block:: yaml

    CLIENT_CN:

*Default:* ``false``

If enabled, Jetconf will use ``commonName`` to identify users.
By default Jetconf is using ``emailAddress`` to identify users.

.. code-block:: yaml

    BACKEND_PACKAGE:

*Default:* ``"jetconf_jukebox"``

This option selects the package with backend bindings that Jetconf will use.
An exact name of the Python package has to be specified here,
and also the package has to be installed in Python's environment.


HTTP_SERVER:
------------

Example
^^^^^^^

.. code-block:: yaml

    HTTP_SERVER:
        DOC_ROOT: "doc-root"
        DOC_DEFAULT_NAME: "index.html"
        API_ROOT: "/restconf"
        API_ROOT_STAGING: "/restconf_staging"
        SERVER_NAME: "jetconf-h2"
        UPLOAD_SIZE_LIMIT: 1
        LISTEN_LOCALHOST_ONLY: false
        PORT: 8443
        DISABLE_SSL: false
        SERVER_SSL_CERT: "server.crt"
        SERVER_SSL_PRIVKEY: "server.key"
        CA_CERT: "ca.pem"
        DBG_DISABLE_CERTS: false

Options
^^^^^^^

.. code-block:: yaml

    DOC_ROOT:

*Default:* ``"doc-root"``

A root directory where regular files will be placed.
All HTTP GET requests outside ``API_ROOT`` are considered as requests for regular files on filesystem.

.. code-block:: yaml

    DOC_DEFAULT_NAME:

*Default:* ``"index.html"``

A default filename in DOC_ROOT and its subdirectories.

.. code-block:: yaml

    API_ROOT:

*Default:* ``"/restconf"``

Defines the base URI of RESTCONF data. All requests for resources inside API_ROOT will be considered as RESTCONF requests.
It is usually not needed to change this value. Example: ``"/restconf" -> https://localhost/restconf/ns:some_resouce``

.. code-block:: yaml

    API_ROOT_STAGING:

*Default:* ``/restconf_staging``

Same as above, except this is for staging data (data edited by user, but not commited yet).

.. code-block:: yaml

    SERVER_NAME:

*Default:* ``"jetconf-h2"``

A value returned in ``"Server: "`` header of HTTP response.

.. code-block:: yaml

    UPLOAD_SIZE_LIMIT:

*Default:* ``1``

A maximum size of incoming data in ``PUT`` or ``POST`` body (in **megabytes**), which the server can handle.

.. code-block:: yaml

    LISTEN_LOCALHOST_ONLY:

*Default:* ``false``

If set to ``true``, the Jetconf HTTP server will only accept incoming connections from *localhost*.

.. code-block:: yaml

    PORT:

*Default:* ``8443``

The TCP port of Jetconf server.

.. code-block:: yaml

    DISABLE_SSL:

*Default:* ``false``

If enabled, the user authentication system based on client certificates will be turned off and user data
will be parsed from HTTP headers. For instance, this change allows you to run Jetconf behind a
load balancer where the TLS connection is terminated and and http request is forwarded to
Jetconf server with relevant headers. Can be combined with ``DBG_DISABLE_CERT``.


.. code-block:: yaml

    SERVER_SSL_CERT:

*Default:* ``"server.crt"``

The location of server SSL certificate in PEM format.

.. code-block:: yaml

    SERVER_SSL_PRIVKEY:

*Default:* ``"server.key"``

The location of server SSL private key in PEM format.

.. code-block:: yaml

    CA_CERT:

*Default:* ``"ca.pem"``

The location of certification authority certificate, which is used for issuing client certificates.

.. code-block:: yaml

    DBG_DISABLE_CERTS:

*Default:* ``false``

If enabled, the user authentication system based on client certificates will be turned off
and every incoming connection will default to "test-user" username. This should never be turned
on in real environment, it is only intended for testing and benchmarking purposes
(no HTTP/2 benchmarking tools support client certificates at this moment).
Can be combined with ``DISABLE_SSL``.

NACM:
-----

Example
^^^^^^^

.. code-block:: yaml

    NACM:
        ENABLED: true
        ALLOWED_USERS: ["superuser@example.com", "admin@example.com"]

Options
^^^^^^^

.. code-block:: yaml

    ENABLED:

*Default:* ``true``

If set to false, NACM rules will not be applied.

.. code-block:: yaml

    ALLOWED_USERS:

*Default:* ``[]``

A list of superusers allowed to edit NACM data. By default no superuser is specified.


Application-specific sections
=============================

Application-specific sections are configuring additional Jetconf settings available in specific implementation Jetconf.
Depends on Jeconf backend package. Typically it configures Jetconf backend settings, that have to be defined by backend developer.

For instance, configuration required by knot-jetconf_ backend package.

.. code-block:: yaml

    KNOT:
        SOCKET: "/tmp/knot.sock"

.. code-block:: yaml

    SOCKET:

*Default:* ``"/tmp/knot.sock"``

A path to KnotDNS control socket.
