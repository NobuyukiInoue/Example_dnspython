# -*- coding: utf-8 -*-

import dns.resolver
import os
import socket
import sys
import time


def main():
    argv = sys.argv
    argc = len(argv)

    if argc < 2:
        exit_msg(argv[0])

    resolvstring = argv[1]

    if argc < 3:
        recordtype = "NS"
    else:
        recordtype = argv[2]

    recordtype = recordtype.upper()

    printmode = False
    if argc >= 4:
        if argv[3].upper() == "TRUE":
            printmode = True

    try:
        answers = ""
        if recordtype == "PTR":
            #answers = dns.reversename.from_address(resolvstring)
            answers = socket.gethostbyaddr(resolvstring)[0]
        else:
            answers = dns.resolver.query(resolvstring, recordtype)

    except Exception as e:
        print(e.args)
        exit(1)

    if recordtype == "SOA":
        result = result_to_list_soa(answers.response.answer[0].items)
        print_result(result, printmode)

    elif recordtype == "NS":
        result = result_to_list_ns(answers.response.answer[0].items)
        print_result(result, printmode)

    elif recordtype == "MX":
        result = result_to_list_mx(answers.response.answer[0].items)
        print_result(result, printmode)
    
    elif recordtype == "A":
        result = result_to_list_a(answers.response.answer[1].items)
        print_result(result, printmode)

    elif recordtype == "CNAME":
        result = result_to_list_ns(answers.response.answer[0].items)
        print_result(result, printmode)

    elif recordtype == "PTR":
        print(answers)

    else:
        print("%s is not defined." %recordtype)


def result_to_list_ns(items):
    result = []
    servername = ""
    for sv in items:
        for col in range(len(sv.target.labels)):
            if col == 0:
                servername = sv.target.labels[col].decode()
            else:
                servername += "." + sv.target.labels[col].decode()
        if servername[-1] == ".":
            servername = servername[:len(servername) - 1]
        result.append(servername)
    result.sort()
    return result


def result_to_list_soa(items):
    result = ""
    zonename = ""
    for sv in items:
        for col in range(len(sv.mname.labels)):
            if col == 0:
                zonename = sv.mname.labels[col].decode()
            else:
                zonename += "." + sv.mname.labels[col].decode()
        if zonename[-1] == ".":
            zonename = zonename[:len(zonename) - 1]

        result += "mname : " + zonename + "\n"
        result += "serial : " + str(sv.serial) + "\n"
        result += "expire : " + str(sv.expire) + "\n"
        result += "minimum : " + str(sv.minimum) + "\n"
        result += "refresh : " + str(sv.refresh) + "\n"
        result += "retry : " + str(sv.retry) + "\n"

    return result


def result_to_list_a(items):
    result = []
    for sv in items:
        result.append(sv.address)
    result.sort()
    return result


def result_to_list_mx(items):
    result = []
    for sv in items:
        result.append(sv)
    result.sort()
    return result


def exit_msg(argv0):
    print("Usage: python %s [resolv string] [record type] <print_flag>" %argv0)
    print("\n"
          "For Example)\n"
          "python {cmd} www.hackerzlab.com a\n"
          "python {cmd} hackerzlab.com ns\n".format(cmd=argv0))
    exit(0)


def print_result(result, printmode):
    if printmode == True:
        for cur in result:
            print(cur)
    else:
        print(result)


if __name__ == "__main__":
    main()