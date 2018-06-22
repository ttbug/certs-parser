#coding=utf-8
'''
获取网站证书并存储到数据库
'''
import re
import ssl
import datetime
import subprocess
import socket
import argparse
from subprocess import PIPE
import OpenSSL

from db import insert_data


# 命令行参数解析
def usage():
    parser = argparse.ArgumentParser(description='Get SSL certs')
    parser.add_argument("-u", "--url", action='store', help="website url.", default = None)
    parser.add_argument("-p", "--port", action="store", help="ssl port", default = 443)

    return parser.parse_args()


class Certs:
    '''
        Get certificate by openssl, socket, ssl. and parse certificate key and values
        insert into mongodb.
    '''

    def __init__(self, host, port=443):
        self.host = host
        self.port = port
    
    def get_certs_by_openssl(self, host, port=443):
        hp = self.host + ':' + str(self.port)
        try:
            p = subprocess.Popen(['openssl', 's_client', '-connect', hp,'-showcerts'],stdin=PIPE,stdout=PIPE,stderr=PIPE)
            out, err = p.communicate()
            return self.certs_format(out)
        except Exception as e:
            print "Error occour: {0}".format(e)
            exit(-1)

    def get_cert_by_scoket(self, host, port=443):
        client = socket.socket()
        client.settimeout(None)
        try:
            client.connect((self.host, int(self.port)))
        except socket.gaierror as e:
            print 'Error connect to server: {0}'.format(e)
            exit(-3)

        clientSSL = OpenSSL.SSL.Connection(OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD), client)
        clientSSL.set_connect_state()

        try:
            clientSSL.do_handshake()
        except OpenSSL.SSL.WantReadError as e:
            print('Error trying to establish an SSL connection: {0}'.format(e))
            exit(-4)
        
        CertDataRaw = str(OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM,
                        clientSSL.get_peer_certificate()))

        return CertDataRaw

    # the easist way
    def get_cert_by_ssl(self, host, port=443):
        try:
            certs = ssl.get_server_certificate((self.host, self.port))
            return certs
        except socket.gaierror as e:
            print 'Error connect: {0}'.format(e)
            exit(-2)


    def certs_format(self, certs):
        #print(certs)
        pattern = re.compile(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', re.DOTALL)
        certs_info = re.findall(pattern, certs)
        certs = ['-----BEGIN CERTIFICATE-----'+cer+'-----END CERTIFICATE-----' for cer in certs_info]

        tmp = '\n'.join(certs)

        return tmp


    def parse_certs(self, certs):
        try:
            ospj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certs)
        except OpenSSL.crypto.Error as e:
            print 'Error occur: {0}'.format(e)
            exit(-5)
        
        CertExpired = ospj.has_expired()
        CertVersion = ospj.get_version()
        CertSigAlgo = ospj.get_signature_algorithm()
        CertSubject = str(ospj.get_subject())[18:-2]
        CertStartDate = ospj.get_notBefore()
        CertEndDate = ospj.get_notAfter()
        CertIssuer = str(ospj.get_issuer())[18:-2]

        return {'CertSubject': CertSubject, 'CertStartDate': CertStartDate,
                'CertEndDate': CertEndDate, 'CertIssuer': CertIssuer,
                'CertSigAlgo': CertSigAlgo, 'CertExpired': CertExpired,
                'CertVersion': CertVersion}


    def parse_cert_extension(self, certs):
        try:
            ospj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certs)
        except OpenSSL.crypto.Error as e:
            print 'Error occur: {0}'.format(e)
            exit(-6)

        extNum = 0
        ExtNameVal = dict()
        while extNum < ospj.get_extension_count():
            extName = str(ospj.get_extension(extNum).get_short_name())
            extVal = str(ospj.get_extension(extNum))
            ExtNameVal[extName] = extVal

            extNum += 1
        
        return ExtNameVal
        


    def run(self):
        #certs = self.get_certs_by_openssl(args.url, args.port)
        #certs = self.get_cert_by_scoket(args.url, args.port)
        certs = self.get_cert_by_ssl(args.url, args.port)

        result = self.parse_certs(certs)
        extresult = self.parse_cert_extension(certs)
        #print extresult
        cert_dict = {'_id':args.url, 'certs':certs}
        cert_dict.update(result)
        cert_dict.update(extresult)
        # insert to mongodb
        insert_data(cert_dict)


if __name__ == "__main__":
    args = usage()
    certs = Certs(args.url, args.port)
    certs.run()