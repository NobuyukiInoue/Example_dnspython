import dns.resolver
import inspect

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
