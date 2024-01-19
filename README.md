# buildDNS
Building dns

`Run node index.js` to start the dns server
and then `dig example2.com @127.0.0.01`


Index and parser have been tested independantly but systemd-resolved is listening on port 53. DNS by default runs on port 53 and you can not set an alternate port for dig