# CSAW Cert App

An intentionally vulnerable ruby/rack SSL/TLS Client Certificate application.  Generates and distributes certs, and maintains a directory of public keys.

Authenticate as 'admin' to obtain the flag.

The code is running at https://csaw.offenseindepth.com/ for the next week or so.

## History

This was used as a challenge in NYU Poly's CSAW CTF 2012.  7 of 15 competing teams were able to solve it.

## Solution

I'll post a solution online in a week or so.  I'll try to link to any solutions posted by the solving teams as well.

## Requirements

* Some version of Ruby >= 1.9.1 (ruby1.9.x)
* Developer libraries for same (ruby1.9.x-dev)
* A working mongodb installation
* rubygems
* bundler

## Development Environment

The Development environment is configured to use Webrick.  Sample CA and Server keypairs are generated on first run.

To install, type;
```bash
bundler install
```

To run
```bash
rackup
````
Notes:
* Both CA certificate and public key must reside (or be symlinked) in the app's /keys directory
** If these are unavailable on first launch, both will be created. 
** You may wish to create your own keypairs
* Ruby 1.8.7 should work, but bundle fails to install Webrick.  Feel free to troubleshoot if you'd prefer.

## Production Environment

The Production environment has been testing under nginx with Phusion Passenger.

A sample nginx config will include:
```
server {
    listen       443;
	root /path/to/certapp/public;
	passenger_enabled on;

    ssl                  on;
    ssl_certificate      /path/to/keys/cert.pem;
    ssl_certificate_key  /path/to/keys/cert.key;
	ssl_client_certificate /path/to/keys/ca.crt;
	ssl_verify_client optional;
	passenger_set_cgi_param	    SSL_CLIENT_CERT $ssl_client_raw_cert;
    ssl_session_timeout  5m;
    ssl_protocols  SSLv3 TLSv1;
    ssl_ciphers  HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers   on;
}
```

Notes:
* The client certificate is passed as an SSL_CLIENT_CERT cgi parameter.
* Server keypair must be made available to nginx
* The CA certificate (but not key) must be made available to nginx
* Both CA certificate and public key must also reside (or be symlinked) in the certapp's /keys directory
** If these are unavailable on first launch, a CA will be created.  It must match the CA cert used by nginx for proper operation.
** You may wish to create your own CA keypair
