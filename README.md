# Example_dnspython

a program that sends DNS requests and displays the answers.


## 1. Example for dns_send_udp_request.py

```
python dns_send_udp_request.py [dns server] [resolv string] [record type]
```

### 1-1. request ANY Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com
```
or
```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com any
```

### 1-2. request A Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com a
```

### 1-3. request CNAME Record

```
python dns_send_udp_request.py 192.168.1.1 www.hackerzlab.com cname
```

### 1-4. request NS Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com ns
```

### 1-5. request MX Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com mx
```

### 1-6. request SOA Record

```
python dns_send_udp_request.py 192.168.1.1 hackerzlab.com soa
```

### 1-7. request PTR Record

```
python dns_send_udp_request.py 192.168.1.1 8.8.8.8 ptr
```

## 2. Example for dns_resolv.py

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
