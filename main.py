#!/usr/bin/env python
# coding: shift-jis

import re
from scapy.all import *
from datetime import datetime
from wrapper.excel_wrapper import ExcelWapper
from wrapper.xml_wrapper import XmlWapper
from wrapper.sqlite3_wrapper import SqlWapper

def get_request_or_response(keyword, contents):
    """ Get HTTP request or response text data

    ex. 
    contents -> "b'HTTP/1.1 200 OK\r\n.........."
    keyword  -> "HTTP"
    output   -> "HTTP/1.1 200 OK\r\n"

    Parameters
    ----------

    keyword : str
        POST, GET, HTTP ... etc

    contents: str
        str(packet['Raw'])
        packet is rdpcap(name).filter[n]

    Returns
    -------

    text : str
        HTTP request or response text data

    """
    pattern = r".*?(" + keyword + r").*?(\\r\\n)"
    match = re.match(pattern, contents)
    if match == None:
        return ""

    # ex. "'bGET /" -> "GET /"
    offset = match.group(0).find(keyword)
    text = match.group(0)[offset:]
    return text


def find_data(packet):
    """ Find HTTP data from packet data.

    If the packet include  http request or response , then pick up its text.
    (Request GET/POST, Response HTTP)

    ex 
    "b'GET / \r\n..................." -> "GET / \r\n"
    "b'HTTP/1.1 200 OK\r\n.........." -> "HTTP/1.1 200 OK\r\n"
    "b'HOGE / \r\n.................." -> None

    Parameters
    ----------

    packet : scapy.layers.l2.Ether
        packet is rdpcap(name).filter(filter)[n]

    Returns
    -------

    text : str
        HTTP request or response text data

    """
    payload = str(packet['Raw'])
    request = get_request_or_response(r"POST", payload)
    request += get_request_or_response(r"GET", payload)
    if len(request) > 0:
        return request
    else:
        # response = get_request_or_response(r"HTTP", payload)
        response = bytes(payload, 'utf8')
        if len(response) > 0:
            return response
        else:
            return None


def analyze_captured_file(name):
    """ Analyze capture file(*.pcap) as HTTP transfferd.

    This function outputs  list data. like this,

    [(timestump, summary, text), (timestump, summary, text), ...]

    touple example.
        ( 2019-03-28T07:49:11.13361,   # index 0
          Ether / IP / TCP 192.168.0.11:49875 > 192.168.0.12:http PA / Raw, #index 1
          GET / HTTP/1.0\r\n ) # index 2

    Parameters
    ----------

    name : str 
        pcap file name

    port : int
        HTTP port number

    Returns
    -------

    text : list
        report data
        [(timestump, summary, text), (timestump, summary, text), ...]

    """
    def filter(p): return Raw in p
    packets = rdpcap(name).filter(filter)
    list = []

    for packet in packets:
        datetime_text = datetime.fromtimestamp(
            float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')

        data = find_data(packet)
        list.append((datetime_text, packet.sprintf("%IP.src%:%TCP.sport%"), packet.sprintf("%IP.dst%:%TCP.dport%"),
         packet.sprintf("%IP.proto%"), packet.summary(), data))

    return list


def print_list(list):
    """ Print analyze_captured_file function's result.

    Parameters
    ----------

    list : list
        analyze_captured_file function's result

    """
    i = 1
    for item in list:
        datetime_text = item[0]
        # host = item[1]
        # dest = item[2]
        # protocal = item[3]
        summary_text = item[4]
        text = item[5]
        print("No:", i, "", datetime_text)
        print("\t", summary_text)
        print("\t", text)
        i += 1


def write_data_to_excel(excel, x, y, item):
    """ Write analyze_captured_file function's result[n] to excel 

    Parameters
    ----------

    excel : objet
        ExcelWapper object

    x : int
        sheet position x

    y : int
        sheet position y

    item : taple
        taple of analyze_captured_file function's result
        ex. 
            result = analyze_captured_file(name, file)
            write_data_to_excel(excel, x, y, result[n]) # <- like this

    """
    datetime_text = item[0]
    host = item[1]
    dest = item[2]
    protocal = item[3]
    summary_text = item[4]
    text = item[5]
    excel.write_value(x + 0,  y, datetime_text)
    excel.write_value(x + 1,  y, host)
    excel.write_value(x + 2,  y, dest)
    excel.write_value(x + 3,  y, protocal)
    excel.write_value(x + 4,  y, summary_text)
    excel.write_value(x + 5,  y, text)


def make_excel_file(list, filename):
    """ Make report excel file

    This function makes a excel file with using ExcelWapper class.
    If you want to know detail, see excel_wrapper.py(docstirng)

    Parameters
    ----------

    list : list
        analyze_captured_file function's result

    filename : str
        Filename of excel.

    filename : str
        Filename of image(jpg / png etc...).

    """

    sheet_name = "ScapyResut"
    excel = ExcelWapper()
    excel.create_book()
    excel.create_sheet(sheet_name)

    x_start = x_pos = 1
    x_size = 6
    y_start = y_pos = 1

    # title
    item = ("TimeStump", "Host", "Dest", "Protocal", "Summary", "Raw data")
    write_data_to_excel(excel, x_pos, y_pos, item)
    y_pos += 1

    # values
    for item in list:
        write_data_to_excel(excel, x_pos, y_pos, item)
        y_pos += 1

    excel.resize_sheet_width()
    excel.draw_table(x_start, x_size, y_start, (y_pos - y_start))

    # save file
    excel.save(filename)

    print("sample:", filename, " created.")

def make_xml_file(list, filename):
    """ Make report xml file

    This function makes a xml file with using XmlWapper class.
    If you want to know detail, see xml_wrapper.py(docstirng)

    Parameters
    ----------

    list : list
        analyze_captured_file function's result

    filename : str
        Filename of xml.

    """

    xml_tree = XmlWapper()
    xml_tree.add_attribute(xml_tree.root, "total", len(list))

    # values
    for item in list:
        node = xml_tree.add_node("Packet")

        datetime_text = item[0]
        host = item[1]
        dest = item[2]
        protocal = item[3]
        summary_text = item[4]
        text = item[5]

        leaf = xml_tree.add_leaf(node, "DateTime")
        leaf.text = datetime_text

        leaf = xml_tree.add_leaf(node, "Host")
        leaf.text = host

        leaf = xml_tree.add_leaf(node, "Dest")
        leaf.text = dest

        leaf = xml_tree.add_leaf(node, "Protocol")
        leaf.text = protocal

        leaf = xml_tree.add_leaf(node, "Summary")
        leaf.text = summary_text

        leaf = xml_tree.add_leaf(node, "Text")
        leaf.text = text

    # save file
    xml_tree.save(filename)

    print("sample:", filename, " created.")

def make_sql_file(list, dbname, tablename):
    """ Make report db file

    This function makes a db file with using SqlWapper class.
    If you want to know detail, see sqlite3_wrapper.py(docstirng)

    Parameters
    ----------

    list : list
        analyze_captured_file function's result

    dbname : str
        db name of sqlite3.

    """

    db = SqlWapper(dbname)
    db.init_table(tablename)

    # values
    for item in list:
        # datetime_text = item[0]
        # host = item[1]
        # dest = item[2]
        # protocal = item[3]
        # summary_text = item[4]
        # text = item[5]
        db.add_row(item)

    # save file
    db.save()

    print("sample:", dbname, " created.")

if __name__ == "__main__":
    """ program of scapy and openpyxl, lxml
        pip install -r requirements.txt
    """

    # 1. sniffing
    # packages = sniff(iface="eth0", count=10)   # sniffing
    # pcap_filename = "sniff.pcap"
    # wrpcap(pcap_filename, packages)            # save sniffing result

    # 2. read from pcap file
    pcap_filename = "sample.pcap"

    rows = analyze_captured_file(pcap_filename)
    print_list(rows) # show on console

    excel_filename = "sniff.xlsx"
    make_excel_file(rows, excel_filename)

    xml_filename = "sniff.xml"
    make_xml_file(rows, xml_filename)

    # txt_filename = "sniff.txt"
    # make_txt_file(rows, txt_filename)

    # sql insert
    """ on kali linux 
        install sqlite3 by command
            apt-get install sqlite3 sqlitebrowser
        to show sql file by command
            sqlitebrowser sniff.db
    """
    sql_name = "sniff.db"
    table_name = "Packet"
    make_sql_file(rows, sql_name, table_name)

    print("sniff and export: completed.")
