import dns.resolver
import inspect

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
