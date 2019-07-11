# Example_dnspython

a program that sends DNS requests and displays the answers.


## 1. Example for dns_send_udp_request.py

```
python dns_send_udp_request.py [dns server] [resolv string] [record type]
```

### Supported record types

* ANY(255)
* A(1)
* NS(2)
* CNAME(5)
* SOA(6)
* PTR(12)
* MX(15)
* TXT(16)
* AAAA(28)
* SRV(33)
* DS(43)
* RRSIG(46)
* DNSKEY(48)
* NSEC3(50)
* NSEC3PARAM(51)
* CAA(257)

### 1-1. request ANY Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com
```
or
```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com any
```
or
```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com 255
```

### 1-2. request A Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com a
```
or
```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com 1
```

### 1-3. request CNAME Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com cname
```
or
```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com 5
```

### 1-4. request NS Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com ns
```
or
```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com 2
```

### 1-5. request MX Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com mx
```
or
```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com 15
```

### 1-6. request SOA Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com soa
```
or
```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com 6
```

### 1-7. request PTR Record

```
python dns_send_udp_request.py 192.168.1.1 8.8.8.8 ptr
```
or
```
python dns_send_udp_request.py 192.168.1.1 8.8.8.8 12
```

### 1-8. request CAA Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com caa
```
or
```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com 257
```

### 1-9. request SRV Record

```
python dns_send_udp_request.py 192.168.1.1 _http._tcp.hackerzlab.com srv
```
or
```
python dns_send_udp_request.py 192.168.1.1 _http._tcp.hackerzlab.com 33
```


## 2. Example for dns_resolv.py

It is a DNS resolver program using dnspython.


### Pre INSTALLATION for dns_resolv.py

* Many distributions have dnspython packaged for you, so you should
  check there first.
* If you have pip installed, you can do `pip install dnspython`
* If not just download the source file and unzip it, then run
  `sudo python setup.py install`


### 2-1. request NS Record

```
python dns_resolv.py [domain_name] ns
```

### 2-2. request MX Record

```
python dns_resolv.py [domain_name] mx
```


### 2-3. request SOA Record

```
python dns_resolv.py [domain_name] soa
```

### 2-4. request CNAME Record

```
python dns_resolv.py [hostname] cname
```

### 2-5. request A Record

```
python dns_resolv.py [hostname] a
```

### 2-6. request PTR Record

```
python dns_resolv.py [ip address] ptr
```
