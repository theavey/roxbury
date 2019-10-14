"""Define a class to interact with some LG soundbars

This work was largely inspired by temescal
(https://github.com/google/python-temescal), and it is distrubuted
under the same license.


"""

#    Copyright 2019 Thomas Heavey
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


import logging

from Crypto.Cipher import AES

import socket
import json
import struct
from threading import Thread
import time


__all__ = ['Roxbury']


logging.basicConfig(level=logging.INFO)
_l = logging.getLogger()


class Roxbury(object):
    iv = b'54eRty@hkL,;/y9U'
    key = b'4efgvbn m546Uy7kolKrftgbn =-0u&~'
    
    def __init__(self, ip='192.168.101.154', get_initial_status=True):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.connect()
        if True:
            self.thread = Thread(target=self.listen, daemon=True)
            self.thread.start()
        self.status = dict()
        if get_initial_status:
            self.get_info()  # get some stuff for status
        
    def encrypt_packet(self, data):
        padlen = 16 - (len(data) % 16)
        for i in range(padlen):
            data = data + chr(padlen)
        data = data.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

        encrypted = cipher.encrypt(data)
        length = len(encrypted)
        prelude = bytearray([0x10, 0x00, 0x00, 0x00, length])
        return prelude + encrypted

    def decrypt_packet(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypt = cipher.decrypt(data)
        logging.debug(f'raw decrypted: {decrypt}')
        padding = decrypt[-1:]
        decrypt = decrypt[:-ord(padding)]
        return str(decrypt, 'utf-8',  # errors='ignore'
                   )

    def listen(self, ):
        data = ['']
        while True:
            try:
                data = self.socket.recv(1)
            except Exception:
                self.socket.connect((self.ip, 9741))
            if data[0] == 0x10:
                data = self.socket.recv(4)
                length = struct.unpack(">I", data)[0]
                data = self.socket.recv(length)
                logging.debug(f'raw: {data}')
                response = self.decrypt_packet(data)
                if response is not None:
                    logging.debug(f'decrypted: {response}')
                    logging.debug(f'unjsoned: {json.loads(response)}')
                    response = json.loads(response)
                    self._set_status(response.get('data', None))
                    logging.info(response)

    def _set_status(self, data):
        if data is None:
            return
        self.status.update(data)
        if 'info' in data:
            self.status.update(data['info'])

    def connect(self, port=9741):
        self.socket.connect((self.ip, port))

    def send_packet(self, data):
        packet = self.encrypt_packet(json.dumps(data))
        try:
            self.socket.send(packet)
        except Exception:
            try:
                self.connect()
                self.socket.send(packet)
            except Exception:
                pass

    @property
    def volume(self):
        return self.status.get('vol', None)

    @volume.setter
    def volume(self, volume):
        self.set_volume(volume)

    def set_mute(self, enable):
        data = {'msg': 'MUTE_SET', 'data': {'mute': enable}}
        self.send_packet(data)

    def set_portable(self, ):
        data = {'msg': 'FUNCTION_SET', 'data': {'type': 2}}
        self.send_packet(data)

    def set_input(self, selection):
        input_dict = {'wifi': 0, 'wi-fi': 0, 'wireless': 0,
                      'bluetooth': 1, 'bt': 1,
                      'portable': 2, 'analog': 2, 'aux': 2,
                      'optical': 4,
                      'hdmi': 6, 'hdmi in': 6, 'hdmiin': 6,
                      'tv arc': 7, 'arc': 7,
                      'lg tv': 12, 'lgtv': 12}
        try:
            num = int(selection)
        except ValueError:
            try:
                num = input_dict[selection.lower()]
            except KeyError:
                raise ValueError('Unrecognized input selection '
                                 '{}.'.format(selection))
        data = {'msg': 'FUNCTION_SET', 'data': {'type': num}}
        self.send_packet(data)
        data = {'msg': 'FUNC_INFO_REQ'}
        self.send_packet(data)
        
    def volume_up(self, ):
        data = {'msg': 'VOLUME_UP'}
        self.send_packet(data)
        
    def volume_down(self, ):
        data = {'msg': 'VOLUME_DOWN'}
        self.send_packet(data)

    def get_info(self):
        data = {'msg': 'PRODUCT_INFO', 'data': {'option': 0}}
        self.send_packet(data)

    def set_volume(self, volume):
        if self.volume is None:
            self.get_info()
            time.sleep(1)
            if self.volume is None:
                # TODO define custom exception for this
                raise ValueError('Could not find volume to set it')
        if self.volume < volume:
            for i in range(volume - self.volume):
                self.volume_up()
        if self.volume > volume:
            for i in range(self.volume - volume):
                self.volume_down()
