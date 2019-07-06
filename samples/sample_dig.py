# コードログ
# どのようにdns-pythonでdigとしてdnsクエリを作成しますか（追加のレコードセクションを含む）。
# https://codeday.me/jp/qa/20190323/462491.html

import dns.name
import dns.message
import dns.query
import dns.flags

def main():
    domain = 'google.com'
    name_server = '8.8.8.8'
    ADDITIONAL_RDCLASS = 65535

    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    request = dns.message.make_query(domain, dns.rdatatype.ANY)
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                    dns.rdatatype.OPT, create=True, force_unique=True)
    response = dns.query.udp(request, name_server)

    print(response.answer)
    print(response.additional)
    print(response.authority)


def print_result(result):
    for cur in result:
        print(cur)


if __name__ == "__main__":
    main()
