.. _examples:

****************
Jetconf Backends
****************

JukeBox
=======


KnotDNS
=======


***************
Jetconf clients
***************

Useful links:

- :ref:`certificates`
- :ref:`configuration`


cURL
====

- `cURL site <https://curl.haxx.se/>`_
- `cURL source <https://github.com/curl/curl>`_

A Swiss-knife tool for HTTP/2.

View data in a terminal with curl
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
User's certificate with ``_curl`` suffix in ``.pem`` format is needed.

After this command you should get some data from Jetconf server in json. Do not forget to set ``<path_to_pem_cert>`` and ``<jetconf server ip address>``::

    ~$ curl --http2 -k --cert-type PEM -E <path_to_pem_cert> -X GET https://<jetconf_server_ip_address>:8443/restconf/data


If ``DISABLE_SSL`` and ``CLIENT_CN`` are both set to ``true``, the following command can be used. ``<username>`` is sent in HTTP header::

    ~$curl --http2-prior-knowledge -H "X-SSL-Client-CN: <username>" -X GET http://<jetconf_server_ip_address>:8443/restconf/data

Jetscreen
=========

- `Public page <https://jetconf.pages.labs.nic.cz/jetscreen>`_
- `Jetscreen source <https://gitlab.labs.nic.cz/jetconf/jetscreen>`_

A prototype of an interactive graphical Jetconf client written in Angular 2.
Works only with the JetConf implementation.

View data with Jetscreen
^^^^^^^^^^^^^^^^^^^^^^^^
User's certificate in ``.pfx`` format must be imported to the browser.

#. Open public Jetscreen page https://jetconf.pages.labs.nic.cz/jetscreen
#. Enter your Jetconf server URL and press *enter* or click the *Reset* button. You may be prompted to select a user certificate.
#. Top-level data containers should then appear.



