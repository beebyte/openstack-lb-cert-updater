# openstack-lb-cert-updater
OpenStack Load Balancer Cert Updater

This script can be used to keep OpenStack load balancers up to date with 
Letsencrypt certificates.

## Basic overview
This script can help out with updating a OpenStack loadbalancers SSL certificates.
Its primary usecase is to keep an OpenStack LB up to date with Letsencrypt certificates automatically
by updating the LB in Letsencrypt/certbot post renewal hooks. Multiple certificates can be uploaded to a single LB/Listener.

## Requirements
This script requires Python, and [uv](https://github.com/astral-sh/uv). uv will take care of all the Python dependencies, including Python itself.

Install uv using: ```curl -LsSf https://astral.sh/uv/install.sh | sh```

## Basic usage:
* Make sure you have an openrc.sh for OpenStack authentication, for beebyte customers they can be download from:
  portal.beebyte.se -> Public cloud -> [user] -> Download openrc.sh
* source openrc.sh
* Run ```openstack-lb-cert-updater.py list-load-balancers``` to get the IDs of the LB and Listener
* Run ```openstack-lb-cert-updater.py set-lb-cert``` to update the LB with a new certificate.

## Examples
### Find the correct LB and listener
```
root@my-server:~/bin# source openrc.sh
root@my-server:~/bin# ./openstack-lb-cert-updater.py list-load-balancers
Name: my-lb
Description: LB for www.example.com
ID: eb217843-42aa-479d-8eb0-1437d8d7a528    <- You want this value
Listener: 178ffeb9-fbc4-4913-a426-97ccee4d74e8
  HTTP 80
  tls_container_ref: None
  sni_container_refs: []

Listener: 73d06d41-4a46-439b-8e4f-72935283bdae   <- And this value
  TERMINATED_HTTPS 443
  tls_container_ref: https://vh-api.beebyte.se:9313/v1/containers/3479e110-3413-4e70-900d-0f109efa38f8
  sni_container_refs: ['https://vh-api.beebyte.se:9313/v1/containers/923b6625-aa32-4204-89d2-075e0bcd4e97']
```
The values you need to update the cert are the LB ID and the ID of the listener that is used for SSL termination.

### Update the LB certs
```
root@mys-server:~/bin# /root/bin/openstack-lb-cert-updater.py set-lb-cert --lb eb217843-42aa-479d-8eb0-1437d8d7a528 --listener 73d06d41-4a46-439b-8e4f-72935283bdae --letsencrypt /etc/letsencrypt/live/example.com/
## Loading data
CertificateBundleManager "new" data
Bundle: CertificateBundle: cert:1305 240 1565 container_id:None

CertificateBundleManager "old" data
Bundle: CertificateBundle: cert:1305 240 1565 container_id:3479e110-3413-4e70-900d-0f109efa38f8
Bundle: CertificateBundle: cert:1305 240 1565 container_id:3479e110-3413-4e70-900d-0f109efa38f8

Certificates have not changed, exiting
```

## Letsencrypt / cron usage
The file letsencrypt-post-hook.sh-sample can be copied to /etc/letsencrypt/renewal-hooks/post/ and modified to keep you certificates up to date.
Don't forget to chmod +x the script file and remove -sample.
