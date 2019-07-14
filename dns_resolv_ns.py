#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dns.resolver
import os
import sys
import time

def main():
    argv = sys.argv
    argc = len(argv)

    if argc < 2:
        exit_msg(argv[0])

    resolvstring = argv[1]

    recordtype = "NS"

    try:
        answers = dns.resolver.query(resolvstring, recordtype)

    except Exception as e:
        print(e.args)
        exit(1)

    result = result_to_list_any(answers.response.answer[0].items)
    print(result)


def result_to_list_any(items):
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


def exit_msg(argv0):
    print("Usage: python %s [domain name]" %argv0)
    exit(0)


if __name__ == "__main__":
    main()
