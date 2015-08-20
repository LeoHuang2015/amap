#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A small scanner to get ip/host server banner and page title"""

import os
import re
import time
import signal
import threading
import socket
import chardet
import lxml.html as H
from multiprocessing.dummy import Pool
import requests

lock = threading.Lock()
threadpool = Pool(processes=200)
TIMEOUT = 5
scan_results = []

def signal_handler(signal, frame):
    print "Ctrl+C pressed.. aborting..."
    threadpool.terminate()
    threadpool.done = True

def handle_result(host, port, result):
    tm = time.time()
    with lock:
        scan_results.append([host, port, result])

def amap_scan(*kw):
    if len(*kw) == 2:
        host, port = kw[0][0], int(kw[0][1])
    else:
        return

    #if host!="sangfor.com.cn":return

    result = None
    rcode, server, title = "", "", ""

    target_url = "http://%s:%s" %(host, port)

    try:
        r = requests.get(target_url, timeout=TIMEOUT, allow_redirects=True)

        title = ""


        # requests依据RFC标准，对于不能确定编码会指定ISO-8859-1，对于中文，基本上都是有问题的，通常是utf-8
        # apparent_encoding 会匹配多个，get_encodings_from_content 误差更大，所以自己使用正则匹配

        # 页面meta获取页面编码，有以下几种情况
        #<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        #<meta charset="gbk" />
        #<meta charset="utf-8">
        #<meta charset="utf-8" />
        #<meta charset="UTF-8" />
        meta_reg = r"<meta.*?charset=['\"]?([^'\"><]*)?.*?>"
        if r.encoding == 'ISO-8859-1':
            #print "[-]", target_url
            #print " requests.utils.get_encodings_from_content(r.content)",  requests.utils.get_encodings_from_content(r.content)
            #print "r.apparent_encoding", r.apparent_encoding

            # requests 默认探测失败，查看页面meta方法获取
            m = re.search(meta_reg, r.text, re.I)
            if m:
                r.encoding = m.group(1)

            else:
                # 没有meta设置编码，直接页面js跳转等, 默认设置为utf-8
                r.encoding = 'utf-8'

        try:
            doc = H.document_fromstring(r.text)
            tag_list = doc.xpath('//%s' % ('title'))

            if tag_list:
                title = tag_list[0].text

        except:
            title = "--------"

        if r.status_code:
            rcode = r.status_code
        if 'Server' in r.headers:
            server = r.headers['Server']

    except KeyboardInterrupt:
        pass

    except requests.exceptions.Timeout, e:
        pass
        #print "[-] Timeout: %s" %(e)

    except Exception, e:
        pass
        #print ("[-] Exception: %s" % e), target_url

    finally:
        result = [target_url, rcode, server, title]

    handle_result(host, port, result)
    return result


def amap_file_check(check_file, result_file=None):
    port_list = [80, 8080]

    scan_list = []

    with open(check_file) as f:
        for line in f:
            host = line.strip()
            if not host:
                continue

            for port in port_list:
                scan_list.append([host, port])


    task = threadpool.map(amap_scan, scan_list)

    threadpool.close()
    threadpool.join()

    vul_results = []
    for x in scan_results:
        #print x
        if x[2]:
            vul_results.append(x)

    if result_file:
        with open(result_file, 'w') as f:
            f.write("[AMAP Scan]Scan %d hosts\n\n" % (len(scan_results)))
            for x in vul_results:
                h, p, r = x
                rs = ""
                tu, rcode, server, title = r
                if title:
                    title = title.replace("\r\n", "\t").replace("\n", "\t").replace("\r", "\t")
                    title = title.encode('utf-8')

                rs = "%s\t%s\t%s\t%s" %(tu, rcode, server, title)
                #print rs
                f.write("%s\n" %(rs))

if __name__ == '__main__':

    input_file = "host.txt"
    output_file = "result_amap.txt"

    amap_file_check(input_file, output_file)

    #amap_scan(["songtaste.com", 80])
