# -*- coding: utf-8 -*-
#
# Usage: python dns_send_udp_request.py [dns server] [resolv string] [record type]
#

import socket
import sys
import time

def main():
    argv = sys.argv
    argc = len(argv)

    if argc < 3:
        exit_data_send(argv[0])

    resolvstring = argv[2]

    if argc < 4:
        recordtype = "ANY"
    else:
        recordtype = argv[3]

    recordtype = recordtype.upper()

    if is_ipv4_addr(resolvstring):
        ipaddr = resolvstring.split(".")
        resolvstring = ipaddr[3] + "." + ipaddr[2] + "." + ipaddr[1] + "." + ipaddr[0] + ".in-addr.arpa"

    if recordtype == "PTR" and ".in-addr.arpa" not in resolvstring:
        print("\"in-addr.arpa\" not in %s" %resolvstring)
        exit(1)

    dnsserver = argv[1]
    PORT = 53
    print("============================================================\n"
          "DNS Server    = %s:%d\n"
          "resolv string = %s\n" 
          "record type   = %s" %(dnsserver, PORT, resolvstring, recordtype))

    data_send = set_data(1, resolvstring, recordtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send a DNS udp request.
    s.sendto(data_send, (dnsserver, PORT))
    time_start = time.time()

    # recv a DNS udp response.
    data_recv, address = s.recvfrom(8192)
    time_end = time.time()

    # display results.
    print("============================================================\n"
          "Reply from %s:%s, length = 0x%04x(%d) byte.\n"
          "Response time ... : %f[ms]\n"
          "============================================================"
            %(address[0], address[1], len(data_recv), len(data_recv), (time_end - time_start)*1000))
    print_recv_data(data_recv)

    s.close()


def exit_data_send(argv0):
    print("Usage: python %s [dns server] [resolv string] [record type]" %argv0)
    print("\n"
          "For Example)\n"
          "python {cmd} 192.168.1.1 www.hackerzlab.com cname\n"
          "python {cmd} 192.168.1.1 hackerzlab.com ns\n"
          "python {cmd} 192.168.1.1 hackerzlab.com mx\n"
          "python {cmd} 192.168.1.1 hackerzlab.com soa\n".format(cmd = argv0))
    exit(0)


def is_ipv4_addr(resolvstr):
    flds = resolvstr.split(".")
    if len(flds) != 4:
        return False
    for oct in flds:
        if not oct.isdecimal():
            return False
        if int(oct) < 0 or int(oct) > 255:
            return False
    return True


def set_data(Transaction_ID, resolvstring, type):
    # Transaction ID
    data = Transaction_ID.to_bytes(2, 'big')

    # Flags
    data += 0x0100.to_bytes(2, 'big')

    # Questions
    data += 0x0001.to_bytes(2, 'big')

    # Answer RRS
    data += 0x0000.to_bytes(2, 'big')

    # Answer RRS
    data += 0x0000.to_bytes(2, 'big')

    # Additional RRS
    data += 0x0000.to_bytes(2, 'big')

    # Queries
    if resolvstring == ".":
        data += 0x00.to_bytes(1, 'big')
    else:
        flds = resolvstring.split(".")
        for name in flds:
            data += len(name).to_bytes(1, 'big')
            data += name.encode(encoding = 'ascii')
        data += 0x00.to_bytes(1, 'big')

    # Type
    data += set_type(type)

    # Class ... IN(0x0001)
    data += 0x0001.to_bytes(2, 'big')

    return data


def set_type(type):
    # Type
    if type == None:
        return 0x00ff.to_bytes(2, 'big')
    elif type == 'A':
        return 0x0001.to_bytes(2, 'big')
    elif type == 'NS':
        return 0x0002.to_bytes(2, 'big')
    elif type == 'CNAME':
        return 0x0005.to_bytes(2, 'big')
    elif type == 'SOA':
        return 0x0006.to_bytes(2, 'big')
    elif type == 'PTR':
        return 0x000c.to_bytes(2, 'big')
    elif type == 'MX':
        return 0x000f.to_bytes(2, 'big')
    elif type == 'TXT':
        return 0x0010.to_bytes(2, 'big')
    elif type == 'AAAA':
        return 0x001c.to_bytes(2, 'big')
    elif type == 'RRSIG':
        return 0x002e.to_bytes(2, 'big')
    else:
        return 0x00ff.to_bytes(2, 'big')


def get_type(int_type):
    """
    RFC 1035
    https://www.ietf.org/rfc/rfc1035.txt

    Wikipedia - List of DNS record type
    https://ja.wikipedia.org/wiki/DNS%E3%83%AC%E3%82%B3%E3%83%BC%E3%83%89%E3%82%BF%E3%82%A4%E3%83%97%E3%81%AE%E4%B8%80%E8%A6%A7
    """
    if int_type == 255:
        return "ANY"
    elif int_type == 1:
        return "A"
    elif int_type == 2:
        return "NS"
    elif int_type == 5:
        return "CNAME"
    elif int_type == 6:
        return "SOA"
    elif int_type == 12:
        return "PTR"
    elif int_type == 15:
        return "MX"
    elif int_type == 16:
        return "TXT"
    elif int_type == 28:
        return "AAAA"
    elif int_type == 43:
        return "DS"
    elif int_type == 46:
        return "RRSIG"
    elif int_type == 48:
        return "DNSKEY"
    else:
        return ""


def get_class(int_class):
    """
    RFC 1035
    https://www.ietf.org/rfc/rfc1035.txt
    """
    if int_class == 1:
        return "IN"
    elif int_class == 2:
        return "CS"
    elif int_class == 3:
        return "CH"
    elif int_class == 4:
        return "HS"
    else:
        return ""


def get_algorithm(byte_algorithm):
    if byte_algorithm == 1:
        return ("MD5", 128)
    elif byte_algorithm == 5:
        return ("SHA1", 160)
    elif byte_algorithm == 8:
        return ("SHA256", 256)
    elif byte_algorithm == 10:
        return ("SHA512", 512)
    else:
        return ("", 0)


def print_recv_data(data):
    print("%04x: Transaction ID: 0x%04x" %(0, (data[0] << 8) + data[1]))

    fld_Flags = (data[2] << 8) + data[3]
    print("%04x: Flags:          0x%04x(%s)" %(2, fld_Flags, bin(fld_Flags)))
    print_flags(fld_Flags)

    fld_Question = (data[4] << 8) + data[5]
    print("%04x: Questions:      0x%04x(%d)" %(4, fld_Question, fld_Question))

    fld_Anser_RRS = (data[6] << 8) + data[7]
    print("%04x: Answer RRS:     0x%04x(%d)" %(6, fld_Anser_RRS, fld_Anser_RRS))

    fld_Authority_RRS = (data[8] << 8) + data[9]
    print("%04x: Authority RRS:  0x%04x(%d)" %(8, fld_Authority_RRS, fld_Authority_RRS))

    fld_Additional_RRS = (data[10] << 8) + data[11]
    print("%04x: Additional RRS: 0x%04x(%d)" %(10, fld_Additional_RRS, fld_Additional_RRS))

    i = 12
    i_current = i
    print("%04x: Querys:" %i)
    i, fld_name = get_name(data, i)
    print("%04x:   Name:         %s" %(i_current, fld_name))

    fld_type = (data[i] << 8) + data[i + 1]
    print("%04x:   Type:         0x%04x(%s)" %(i, fld_type, get_type(fld_type)))
    i += 2

    fld_class = (data[i] << 8) + data[i + 1]
    print("%04x:   Class:        0x%04x(%s)" %(i, fld_class, get_class(fld_class)))
    i += 2

    get_answer(data, i)


def print_flags(flags):
    QR = (flags & 0x8000) >> 15
    if QR == 0:
        print("        QR(%d)     ... Query" %QR)
    elif QR == 1:
        print("        QR(%d)     ... Response" %QR)

    OPCODE = (flags & 0x7800) >> 11
    if OPCODE == 0:
        print("        OPCODE(%d) ... standard query" %OPCODE)
    elif OPCODE == 1:
        print("        OPCODE(%d) ... inverse query" %OPCODE)
    elif OPCODE == 2:
        print("        OPCODE(%d) ... server status request" %OPCODE)

    AA = (flags & 0x0400) >> 10
    if AA == 0:
        print("        AA(%d)     ... Not Authoritative" %AA)
    elif AA == 1:
        print("        AA(%d)     ... Authoritative" %AA)

    TC = (flags & 0x0200) >> 9
    if TC == 0:
        print("        TC(%d)     ... Did not Flagment" %TC)
    elif TC == 1:
        print("        TC(%d)     ... Flagment occur" %TC)

    RD = (flags & 0x0100) >> 8
    if RD == 0:
        print("        RD(%d)     ... Recursion Query" %RD)
    elif RD == 1:
        print("        RD(%d)     ... Repeat Query" %RD)

    RA = (flags & 0x0080) >> 7
    if RA == 0:
        print("        RA(%d)     ... Recursion Available is True" %RD)
    elif RA == 1:
        print("        RA(%d)     ... Recursion Available is False" %RD)

    Reserve = (flags & 0x0030) >> 7
    print("        Reserve(%d)" %Reserve)

    RCODE = (flags & 0x0003)
    if RCODE == 0:
        print("        RCODE(%d)  ... No Error" %RCODE)
    elif RCODE == 1:
        print("        RCODE(%d)  ... Format Error" %RCODE)
    elif RCODE == 2:
        print("        RCODE(%d)  ... Server Error" %RCODE)
    elif RCODE == 3:
        print("        RCODE(%d)  ... Name Error" %RCODE)
    elif RCODE == 4:
        print("        RCODE(%d)  ... undefined" %RCODE)
    elif RCODE == 5:
        print("        RCODE(%d)  ... Reject" %RCODE)


def get_answer(data, i):
    while i < len(data):
        print("%04x: Answers:" %i)
        result_bits = ((data[i] << 8) + data[i + 1]) & 0xC000
        if result_bits == 0xc000:
            result_pos = ((data[i] << 8) + data[i + 1]) & 0x3fff
            _, name = get_name(data, result_pos)
            print("%04x:   Name:         %s" %(i, name))
            i += 2
        elif result_bits == 0x8000:
            i += 2
        elif result_bits == 0x4000:
            i += 2
        elif data[i] == 0x00:
            print("%04x:   Name:         <Root>" %i)
            i += 1

        fld_type = (data[i] << 8) + data[i + 1]
        type_name = get_type(fld_type)
        print("%04x:   Type:         0x%04x(%s)" %(i, fld_type, type_name))
        i += 2

        fld_class = (data[i] << 8) + data[i + 1]
        print("%04x:   Class:        0x%04x(%s)" %(i, fld_class, get_class(fld_class)))
        i += 2

        fld_ttl = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3] 
        print("%04x:   Time to live: 0x%08x(%d)" %(i, fld_ttl, fld_ttl))
        i += 4

        fld_data_length = (data[i] << 8) + data[i + 1]
        print("%04x:   data_length:  0x%04x(%d)" %(i, fld_data_length, fld_data_length))
        i += 2

        if type_name == "NS":
            i_current = i
            i, result = get_name(data, i)
            print("%04x:   Name:         %s" %(i_current, result))

        elif type_name == "MX":
            fld_Preference = (data[i] << 8) + data[i + 1]
            print("%04x:   fld_Preference:  0x%04x(%d)" %(i, fld_Preference, fld_Preference))
            i += 2

            i_current = i
            i, result = get_name(data, i)
            print("%04x:   Mail exchange:   %s" %(i_current, result))

        elif type_name == 'SOA':
            i_current = i
            i, primary_name_server = get_name(data, i)
            print("%04x:   Primary name server:  %s" %(i_current, primary_name_server))

            i_current = i
            i, Responsivle_authoritys_mailbox = get_name(data, i)
            print("%04x:   Responsivle authoritys mailbox:  %s" %(i_current, Responsivle_authoritys_mailbox))

            Serial_number = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Serial number:     0x%08x(%d)" %(i, Serial_number, Serial_number))
            i += 4

            Refresh_interval = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Refresh interval:  0x%08x(%d)" %(i, Refresh_interval, Refresh_interval))
            i += 4

            Retry_interval = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Retry interval:    0x%08x(%d)" %(i, Retry_interval, Retry_interval))
            i += 4

            Expiration_limit = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Expiration limit:  0x%08x(%d)" %(i, Expiration_limit, Expiration_limit))
            i += 4

            Minimum_TTL = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Minimum TTL:       0x%08x(%d)" %(i, Minimum_TTL, Minimum_TTL))
            i += 4

        elif type_name == 'A' or type_name == 'CNAME':
            if fld_data_length == 4:
                print("%04x:   Addr:         %d.%d.%d.%d" %(i, data[i], data[i + 1], data[i + 2], data[i + 3]))
                i += 4
            else:
                i_current = i
                i, result = get_name(data, i)
                print("%04x:   Primary name: %s" %(i_current, result))

        elif type_name == "TXT":
            fld_Text = data[i:i + fld_data_length]
            print("%04x:   Text: %s" %(i, fld_Text))
            i += fld_data_length

        elif type_name == "RRSIG":
            i_start = i
            fld_Type_covered = (data[i] << 8) + data[i + 1]
            print("%04x:   Type covered:     0x%04x(%d)" %(i, fld_Type_covered, fld_Type_covered))
            i += 2

            fld_Algorithm = data[i]
            print("%04x:   Algorithm:        0x%04x(%s)" %(i, fld_Algorithm, get_algorithm(fld_Algorithm)[0]))
            i += 1

            fld_Labels = data[i]
            print("%04x:   Labels:           0x%02x(%d)" %(i, fld_Labels, fld_Labels))
            i += 1

            fld_Original_TTL = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Original TTL:     0x%08x(%d)" %(i, fld_Original_TTL, fld_Original_TTL))
            i += 4

            fld_Signature_expiration = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   fld_Signature_expiration: 0x%08x(%d)" %(i, fld_Signature_expiration, fld_Signature_expiration))
            i += 4

            fld_Time_signed =  (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("%04x:   Time signed:      0x%08x(%d)" %(i, fld_Time_signed, fld_Time_signed))
            i += 4

            fld_Id_of_signing_key = (data[i] << 8) + data[i + 1]
            print("%04x:   Id of signing key:  0x%08x(%d)" %(i, fld_Id_of_signing_key, fld_Id_of_signing_key))
            i += 2

            i_current = i
            i, result = get_name(data, i)
            print("%04x:   Signer's name: %s" %(i_current, result))

            signature_size = fld_data_length - (i - i_start)

            i_current = i
            i, result = get_Signature(data, i, signature_size)
            print("%04x:   Signature: " %i_current)
            print_result(result)

        elif type_name == "DNSKEY":
            i_start = i
            fld_Flags = (data[i] << 8) + data[i + 1]
            print("%04x:   Flags:     0x%04x(%d)" %(i, fld_Flags, fld_Flags))
            i += 2

            fld_Protocol = data[i]
            print("%04x:   Protocol:  0x%04x(%d)" %(i, fld_Protocol, fld_Protocol))
            i += 1

            fld_Algorithm = data[i]
            print("%04x:   Algorithm: 0x%04x(%s)" %(i, fld_Algorithm, get_algorithm(fld_Algorithm)[0]))
            i += 1

            fld_public_key_length = fld_data_length - (i - i_start) + 1
            fld_public_key = data[i:i + fld_public_key_length]
            print("%04x:   Public Key:" %i)
            print_result_bin(fld_public_key)
            i += fld_public_key_length

        elif type_name == "DS":
            i_start = i
            fld_Key_id = (data[i] << 8) + data[i + 1]
            print("%04x:   Key_id:     0x%04x(%d)" %(i, fld_Key_id, fld_Key_id))
            i += 2

            fld_Algorithm = data[i]
            print("%04x:   Algorithm:  0x%04x(%s)" %(i, fld_Algorithm, get_algorithm(fld_Algorithm)[0]))
            i += 1

            fld_Digest_type = data[i]
            print("%04x:   Digest type: 0x%04x(%d)" %(i, fld_Digest_type, fld_Digest_type))
            i += 1

            print("%04x:   Public Key:" %i)
            fld_Public_Key_size = fld_data_length - (i_start - i) + 1
            fld_public_key = data[i:i + fld_Public_Key_size]
            print_result(fld_public_key)
            i += fld_public_key_length

        elif type_name == "AAAA":
            print("%04x:   Addr:         %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" %(i,
                data[i], data[i + 1], data[i + 2], data[i + 3],
                data[i + 4], data[i + 5], data[i + 6], data[i + 7],
                data[i + 8], data[i + 9], data[i + 10], data[i + 11],
                data[i + 12], data[i + 13], data[i + 14], data[i + 15]))
            i += fld_data_length

        elif type_name == "PTR":
            i_current = i
            i, result = get_name(data, i)
            print("%04x:   Domain Name: %s" %(i_current, result))

        else:
            fld_other = data[i:i + fld_data_length]
            print("%04x:   Data: %s" %(i, fld_other))
            i += fld_data_length


def get_name(data, i):
    result = ""
    while i < len(data):
        fld_length = data[i]
        if fld_length == 0:
            if result == "":
                result += "<Root>"
            i += 1
            break

        if i + 1 >= len(data):
            break

        result_bits = ((data[i] << 8) + data[i + 1]) & 0xC000
        if result_bits == 0xc000:
            result_pos = ((data[i] << 8) + data[i + 1]) & 0x3fff
            _, pre_name = get_name(data, result_pos)
            result += "[." + pre_name + "]"
            i += 2
            break
        elif result_bits == 0x8000:
            i += 2
            break
        elif result_bits == 0x4000:
            i += 2
            break
        else:
            i += 1

        if len(result) > 0:
            result += "."

        for n in range(fld_length):
            if i + n >= len(data):
                return i + n, result
            result += chr(data[i + n])

        i += fld_length
        if i >= len(data):
            break

    return i, result


def get_Signature(data, i, size):
    result = ""
    max_i = i + size
    while i < max_i:
        result += chr(data[i])
        i += 1
    return i, result


def print_result(target_str):
    print("                   ", end = "")
    col = 1
    for i in range(len(target_str)):
        if col % 16 == 0:
            print(" %02x" %ord(target_str[i]))
            print("                   ", end = "")
        else:
            print(" %02x" %ord(target_str[i]), end = "")
        col += 1
    print()


def print_result_bin(target_str):
    print("                   ", end = "")
    col = 1
    for i in range(len(target_str)):
        if col % 16 == 0:
            print(" %02x" %ord(chr(target_str[i])))
            print("                   ", end = "")
        else:
            print(" %02x" %ord(chr(target_str[i])), end = "")
        col += 1
    print()


if __name__ == "__main__":
    main()
