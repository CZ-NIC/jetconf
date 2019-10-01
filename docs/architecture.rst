.. include:: references.rst
.. _architecture:

************
Architecture
************

Jetconf is an implementation of the RESTCONF_ protocol for remote
management of network devices and services.

`YANG 1.1`_ data modelling language is also fully supported.

JetConf is written in Python 3 language and available as open source
software under the terms of the `GNU GPLv3`_ license.

Requirements and Restrictions
=============================

Jetconf is a compliant RESTCONF_ implementation supporting all mandatory features.

Although it is written in Python, it should be fast enough to support
large configuration databases with moderate rate of changes. A typical
use can may be an authoritative TLD name server in which Jetconf
covers both server management and domain provisioning.

Jetconf supports only the **JSON** data encoding, i.e. media types with
the ``+json`` structured syntax suffix, such as ``application/yang.data+json``.

Jetconf supports only `HTTP/2`_ transport. Entity tags (ETag headers) can
be generated for all data resources, whereas timestamps (Last-Modified
headers) are supported for all container-like resources, i.e. not for
individual leaf and leaf-list instances.

Datastore
=========

Jetconf uses YANGSON_ library, which is responsible for *storage*,
*validation* and *manipulation* with YANG data. This library utilizes an
in-memory persistent structure called *"Zipper"* where the YANG data
are kept in.

Jetconf also provides an option to serialize data into ``.json``
file on each commit, which ensures that all configuration data will
be persistent among server startups.

Additionally, the datastore can have an access control module
associated with it. If so, every read/write operation will be verified
with this ACM.

Access Control
==============

The current version of Jetconf implements NACM_ access control
system, which enables to specify fine-grained access permissions to
particular data resources.

The NACM data can only be edited by privileged users in startup configuration.

Jetconf Server Loop
===================

#. The client opens a secure TLS connection.


#. The client is authenticated via a client certificate. The
   certificate of the CA that issued the client certificate needs to
   be specified in the configuration file. The *e-mail* or *commonName* field obtained
   from the client certificate is henceforth used as the username,
   in particular for access control. If the client cannot be
   authenticated, for example because his certificate has expired or
   because it was not issued by correct CA, the connection is terminated.

#. The server waits for an incoming client request.

#. A received request is parsed and handed over to the appropriate
   component. If the media type specified is not supported (in
   particular, is not ``+json``), ``415 Unsupported Media Type`` is sent,
   If the message is otherwise invalid, ``400 Bad Request`` is sent.

#. The NACM data is queried to determine which groups the user is a
   member of.

#. Depending on the type of the request (read, write or RPC operation
   invocation) and the Request-URI, the required permissions are
   determined, and the NACM database is checked to verify that the
   user possess all of them. If not, ``403 Forbidden`` is sent.

#. If the request is an RPC operation, it is invoked and an
   appropriate reply or error message generated.

#. If the request is a read operation, the corresponding data are retrieved
   from the datastore and formatted into a reply, or an error status
   code is returned.

#. If the request is a write operation, the changes are applied using
   a persistent structure API (so that the original unmodified
   configuration remains available). The new configuration is passed to
   the *YANGSON* library for validation. If the validation succeeds, the
   new configuration is written to non-volatile memory, and passed to
   server instrumentation that applies the necessary changes. An
   appropriate response or error code is generated and sent.

#. After finishing one of the steps 7, 8 or 9, the server returns to step 3.

Python Modules
==============

* ``rest_server``: a module providing the HTTP/2 and user authentication
  functionality for REST operations,
* ``http_handlers``: handlers connecting HTTP requests to datastore
  operations,
* ``data``: datastore implementation,
* ``nacm``: basic NACM implementation,
* ``config``: a module for reading and parsing the config file,
* ``helpers``: static helper classes shared across modules,
* ``op_internal``: implementation of Jetconf internal RPCs,
* ``errors``: definition of exceptions used in Jetconf.
