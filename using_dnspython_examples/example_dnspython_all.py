import dns.resolver
import inspect

print("===================================================================\n"
      "dns.resolver.query(\".\", \"ns\")\n"
      "===================================================================")

answers = dns.resolver.query(".", "ns")
print(answers)
print(dir(answers))
print(vars(answers))
flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"ec2-52-1-2-3.compute-1.amazonaws.com\", \"a\")\n"
      "===================================================================")

answers = dns.resolver.query("ec2-52-1-2-3.compute-1.amazonaws.com", "a")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"www.connpass.com\", \"cname\")\n"
      "===================================================================")

answers = dns.resolver.query("www.connpass.com", "cname")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"52.in-addr.arpa\", \"ns\")\n"
      "===================================================================")

answers = dns.resolver.query("52.in-addr.arpa", "ns")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"3.2.1.52.in-addr.arpa\", \"ptr\")\n"
      "===================================================================")

answers = dns.resolver.query("3.2.1.52.in-addr.arpa", "ptr")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)

print("===================================================================\n"
      "dns.resolver.query(\"jp.\", \"soa\")\n"
      "===================================================================")

answers = dns.resolver.query("jp.", "soa")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"jp.\", \"dnskey\")\n"
      "===================================================================")

answers = dns.resolver.query("jp.", "dnskey")

print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"jp.\", \"ds\")\n"
      "===================================================================")

answers = dns.resolver.query("jp.", "ds")
print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"jp\", \"nsec3param\")\n"
      "===================================================================")

answers = dns.resolver.query("jp.", "nsec3param")
print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)


print("===================================================================\n"
      "dns.resolver.query(\"_http._tcp.update.freebsd.org\", \"srv\")\n"
      "===================================================================")

answers = dns.resolver.query("_http._tcp.update.freebsd.org", "srv")
print(answers)
print(dir(answers))
print(vars(answers))
print(inspect.getmembers(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)
