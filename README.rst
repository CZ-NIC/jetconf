.. |date| date::

*******************************
JetConf with disable SSL option
*******************************
**ssl** branch of **Jetconf** project allow you to disable SSL in *YAM* configuration file::

    DISABLE_SSL: true

and read header SSL ``x-ssl-client-cn`` to establish the user making the request.

Http request will be made by user ``example@mail.cz`` which is added to header::

    # get root configuration data
    curl --http2-prior-knowledge -H "x-ssl-client-cn: example@mail.cz" -X GET "http://localhost:8443/restconf/data"

This allows you to run Jetconf behind a load balancer like HAproxy, where you can terminate the TLS connection, add necessary headers and forward the http request to Jetconf.::

    # forward SSL headers to jetconf
    http-request set-header X-SSL                       %[ssl_fc]
    http-request set-header X-SSL-Client-Verify         %[ssl_c_verify]
    http-request set-header X-SSL-Client-DN             %{+Q}[ssl_c_s_dn]
    http-request set-header X-SSL-Client-CN             %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-SSL-Issuer                %{+Q}[ssl_c_i_dn]
    http-request set-header X-SSL-Client-Not-Before     %{+Q}[ssl_c_notbefore]
    http-request set-header X-SSL-Client-Not-After      %{+Q}[ssl_c_notafter]

