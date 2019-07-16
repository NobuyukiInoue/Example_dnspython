# Example_dnspython

It is a DNS resolver program using dnspython.

sends a DNS UDP request and outputs a response
dns_send_udp_request.py is moved to https://github.com/NobuyukiInoue/pyDNSdump

### Pre INSTALLATION for dns_resolv.py

* Many distributions have dnspython packaged for you, so you should
  check there first.
* If you have pip installed, you can do `pip install dnspython`
* If not just download the source file and unzip it, then run
  `sudo python setup.py install`

## Execution example

### 1-1. request NS Record

```
python dns_resolv.py [domain_name] ns
```

### 1-2. request MX Record

```
python dns_resolv.py [domain_name] mx
```


### 1-3. request SOA Record

```
python dns_resolv.py [domain_name] soa
```

### 1-4. request CNAME Record

```
python dns_resolv.py [hostname] cname
```

### 1-5. request A Record

```
python dns_resolv.py [hostname] a
```

### 1-6. request PTR Record

```
python dns_resolv.py [ip address] ptr
```
