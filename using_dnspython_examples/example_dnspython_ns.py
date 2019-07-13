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
