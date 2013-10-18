#!/usr/bin/python
#coding: utf-8

__author__ = 'yongfengxia'

'''
curl http://serverip:8787/?ip=targetIp
wget -O - http://serverip:8787/?ip=targetIp
'''

import paramiko
from BaseHTTPServer import BaseHTTPRequestHandler
import urlparse
import re

NGINX_SERVER_IP = ''
NGINX_SERVER_SSH_PORT = 36000
NGINX_SERVER_USER = "root"
NGINX_SERVER_PASSWD = "xxx"
REMOTE_WHITELIST_PATH = "/etc/nginx/whiteList.txt"


class GetHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_path = urlparse.urlparse(self.path)
        if parsed_path == '/favicon.ico':
            ico = None
            with open('./favicon.ico', 'r') as fh:
                ico = fh.readall()
            self.send_response(200)
            self.send_header('Content-Type', 'image/x-icon')
            self.end_headers()
            self.wfile.write(ico)
            return
        else:
            queryList = parsed_path.query.split('=')

            is_correct = True
            pattern = re.compile(r'^((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))$')
            if len(queryList) != 2 or queryList[0].strip() != 'ip' or pattern.match(queryList[1].strip()) is None:
                is_correct = False

            message = ''
            not_duplication = True
            if is_correct:
                ip = queryList[1].strip()
                channel = paramiko.Transport((NGINX_SERVER_IP, NGINX_SERVER_SSH_PORT))
                channel.connect(NGINX_SERVER_USER, NGINX_SERVER_PASSWD)
                sftp = paramiko.SFTPClient.from_transport(channel)
                sftp.get(REMOTE_WHITELIST_PATH, 'whiteList.txt')

                with open('whiteList.txt', 'rw') as fh:
                    whiteList = fh.readlines()
                    for line in whiteList:
                        if ip == line.strip():
                            not_duplication = False
                            break
                    if not_duplication:
                        whiteList.append(ip)
                        fh.write('\n'.join(whiteList))
                if not_duplication:
                    sftp.put('whiteList.txt', REMOTE_WHITELIST_PATH)

                    # 重新加载Nginx配置文件
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(NGINX_SERVER_IP, NGINX_SERVER_SSH_PORT, NGINX_SERVER_USER, NGINX_SERVER_PASSWD)
                    _, out, _ = ssh_client.exec_command('/etc/init.d/nginx reload')
                    ssh_client.close()

                    resultList = out.readlines()
                    resultList.append(u'添加白名单成功！')
                    message = '\r\n'.join(resultList)

                # 记得关闭SSH连接
                channel.close()
            else:
                message = u"添加白名单失败，请求参数有误！"

            if not not_duplication:
                message = u"添加白名单失败，该ip已存在白名单中！"

            message += '\r\n'

            self.send_response(200)
            self.end_headers()
            self.wfile.write(message.encode('utf-8'))
            return

if __name__ == '__main__':
    from BaseHTTPServer import HTTPServer
    server = HTTPServer(('0.0.0.0', 8787), GetHandler)
    print 'Starting server, use <Ctrl-C> to stop'
    server.serve_forever()