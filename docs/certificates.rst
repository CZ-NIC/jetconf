.. include:: references.rst
.. _certificates:

***************************
Generating SSL Certificates
***************************

This tutorial explains how to generate self-signed certificates for the Jetconf server
and clients using OpenSSL_. Example certificates can be found in ``data`` subdirectory.

.. warning::

    Self-signed certificates are of course not considered trustworthy
    by web browsers and operating systems, so they are only suitable for testing.

Two bash scripts to help generate SSL certificates are placed in ``/utils/cert_gen`` directory

* ``gen_server_cert.sh`` is used once for generating the server certificate.
* ``gen_client_cert.sh`` is used repeatedly for creating client certificates.

Their usage is described below.

**Installing OpenSSL**

To start with, check that OpenSSL is installed.
If not, it should be available as a package for your operating system::

    $ apt-get install openssl


Certification Authority
=======================

The generated server and client certificates have to be signed by a Certification Authority (CA).
For testing purposes, though, a self-signed CA-like certificate will do.

.. warning::

    For production uses, a trusted CA should always be used.

The easiest, but least secure, way is to use the pre-generated CA-like certificate and
private key from the files ``ca.pem`` and ``ca.key`` available from the ``utils/cert_gen`` directory.

Alternatively, the CA-like certificate and key can be generated using the procedure below.

Generate your own CA-like certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Make or move to your working directory::

    $ mkdir my_ca_cert
    $ cd my_ca_cert

Generate ``ca.key``. see `genrsa <https://www.openssl.org/docs/manmaster/man1/genrsa.html>`_::

    $ openssl genrsa -out ca.key 2048

Generate ``ca.pem`` certificate. see `x509 <https://www.openssl.org/docs/manmaster/man1/openssl-x509.html>`_::

    $ openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.pem

Some parameters of the certificate have to be filled in.
They are not terribly important for testing purposes. For example::

    Country Name (2 letter code) [AU]:CZ
    State or Province Name (full name) [Some-State]:
    Locality Name (eg, city) []:
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:Example CA
    Organizational Unit Name (eg, section) []:exca.cz
    Common Name (e.g. server FQDN or YOUR name) []:mail@exca.cz
    Email Address []:mail@exca.cz

Server Certificate
==================
To generate a new server certificate for JetConf that will be accepted even by
the more pedantic web browsers like Chrome, just run the provided
``gen_server_cert.sh`` script.

The script can be used in one of the two following ways.

The command will generate a new server private key along with the certificate::

    $ ./gen_server_cert.sh <out_file_suffix> <domain/ip>

In this case, the name of the private key file passed to the script as the *<server_key>* argument::

    $ ./gen_server_cert.sh <out_file_suffix> <domain/ip> <server_key>

The script autodetects if the certificate is being issued for a domain
name or an IP address *<domain/ip>*, and sets the appropriate SAN value.

For example, this command will create a certificate named ``server_example.crt``
for ``example.com`` domain with new private key ``server_example.key``::

    $ ./gen_server_cert.sh example example.com

If you want this certificate to be accepted by your web browser,
the issuing CA's certificate needs to be imported to your browser.

.. warning::

    It is strongly recommended to do not import the provided CA's
    certificate ``ca.pem`` to your production browser, as its private key is
    publicly known. If you do so, someone could perform a MITM attack to
    any connection with an SSL-protected website.

Client Certificate
==================

The ``gen_client_cert.sh`` script is intended for generating client certificates
signed by the previously created CA-like certificate.

The script is used simply as follows::

    $ ./gen_client_cert.sh <email_address>

The issued certificate will use the email address passed in the argument is used as the
``emailAddress DN`` and ``commonName`` parameter of the client certificate.
Also, the email address identifies the client to the JetConf server by default.

For example, the command::

    $ ./gen_client_cert.sh joe@example.net

will generate the following files:

- ``joe@example.net.pem`` - the client certificate
- ``joe@example.net.key`` - the client private key
- ``joe@example.net_curl.pem`` - the previous 2 files combined and protected by a password. Some utilities, such as curl_, expect the client certificate in this format.
- ``joe@example.net.pfx`` - *PKCS#12* format for browsers. The password is the email address, i.e. ``joe@example.net`` in this case.

