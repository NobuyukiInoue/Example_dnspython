import dns.resolver
import inspect

print("===================================================================\n"
      "dns.resolver.query(\"3.2.1.52.in-addr.arpa\", \"ptr\")\n"
      "===================================================================")

answers = dns.resolver.query("3.2.1.52.in-addr.arpa", "ptr")

print(answers)
print(dir(answers))
print(vars(answers))

flds = [data for data in answers]
print(flds)
print(answers.response)
