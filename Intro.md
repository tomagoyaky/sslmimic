This is a quick overview for using SSLMimic.

# Introduction #

SSLMimic is a tool for inspecting HTTP and HTTPS conversations.

Here is a quickstart example:

# Details #

  * First, download and expand the tar ball.
(Navigate to release page, download, untar)

  * cd into the expanded directory and run the command with the following flags:
```
./sslmimic.py -i -d
```
```
2010-08-06 14:58:31,472 WARNING Cert file: star.pem does not exist, will create
2010-08-06 14:58:31,486 INFO Running command: openssl req -newkey rsa:1024 -keyout "/tmp/ssl_proxy4l-41f" -nodes -x509  -days 365 -out "/tmp/ssl_proxy4MlVe3" -subj "/C=US/ST=**INSECURE CONNECTION**/L=**INSECURE CONNECTION**/O=**INSECURE CONNECTION**/OU=**INSECURE CONNECTION**/CN=*" -set_serial 0 -days 1 -batch
Generating a 1024 bit RSA private key
.......++++++
...........++++++
writing new private key to '/tmp/ssl_proxy4l-41f'
-----
2010-08-06 14:58:31,642 INFO Successfully created star.pem
2010-08-06 14:58:31,642 DEBUG Application Log: /var/log/ssl_proxy.log
2010-08-06 14:58:31,642 DEBUG Access Log: /var/log/ssl_proxy_access.log
2010-08-06 14:58:31,643 INFO Now starting proxy
2010-08-06 14:58:31,643 INFO Listening on 0.0.0.0 port 1443 ...
```

We can see here that the first run the program creates an SSL cert to use (if it did not already exist)

  * Configure your web browser to point at the proxy
(Localhost:1443)

Note that your browser will produce SSL warnings, and you'll need to add exceptions for
the SSL secured sites which you visit.
Watch the content fly.