import dns.resolver
import inspect

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
