import dns.resolver
import inspect

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
