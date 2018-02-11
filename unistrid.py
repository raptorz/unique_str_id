# -*- coding: utf-8 -*-
"""
    unique_str_id
    Convert an integer ID to an unique string.
    ~~~~~~~~~~~~~~~~

    :copyright: 2018 by raptor.zh@gmail.com.
"""
import array
import math
import os
import struct


class UniqueStringID(object):
    def __init__(self, key, chars=None, length=8, bits_id=27, secure_level=1):
        if chars is None:
            chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.chars = chars
        self.length = length
        self.key = key
        self.bits_id = bits_id
        self.bits_target = int(math.log(math.pow(len(chars), length)) / math.log(2))
        if self.bits_target > 64:
            raise ValueError("Target length too long!")
        if bits_id > int(self.bits_target / 8) * (8 - secure_level):
            raise ValueError("Target length too short!")
        self.max_id = int(math.exp(bits_id * math.log(2)))
        self.bits_encrypt = self.bits_target - self.bits_target % 8

    def rc4init(self):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + ord(self.key[i % len(self.key)])) & 0xFF
            S[i], S[j] = S[j], S[i]
        return S
            
    def rc4(self, data):
        out = []
        S = self.rc4init()
        i = j = 0
        for c in data:
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(c ^ S[(S[i] + S[j]) & 0xFF])
        return out
    
    def merge(self, id, nonce):
        bytes_encrypt = int(self.bits_encrypt / 8)
        bits_per_piece = int((self.bits_id + bytes_encrypt - 1) / bytes_encrypt)
        bits_last_piece = int(self.bits_id % bits_per_piece)
        bits = bits_per_piece
        mask_piece = 0xFF >> (8 - bits)
        mask_nonce = 0xFF >> bits
        data = []
        for i in range(bytes_encrypt):
            if i == bytes_encrypt - 1:
                bits = bits_last_piece
                mask_piece = 0xFF >> (8 - bits)
                mask_nonce = 0xFF >> bits
            c = (id & mask_piece) << (8 - bits)
            id = id >> bits
            data.insert(0, c | (nonce & mask_nonce))
            nonce = nonce >> (8 - bits)
        return data, nonce
    
    def parse(self, data):
        bytes_encrypt = int(self.bits_encrypt / 8)
        if len(data) != bytes_encrypt:
            raise ValueError("Invalida data length!")
        bits_per_piece = int((self.bits_id + bytes_encrypt - 1) / bytes_encrypt)
        bits_last_piece = int(self.bits_id % bits_per_piece)
        out = 0
        for i in range(bytes_encrypt):
            bits = 8 - (bits_per_piece if i > 0 else bits_last_piece)
            c = data[i] >> bits
            out = (out << (8 - bits)) | c
        return out
    
    def encode(self, data):
        out = []
        for i in range(self.length):
            out.insert(0, self.chars[data % len(self.chars)])
            data = int(data / len(self.chars))
        return "".join(out)
    
    def decode(self, code):
        data = 0
        for c in code:
            i = self.chars.index(c)
            data = data * len(self.chars) + i
        return data

    def encrypt(self, id):
        mask = 0xFFFFFFFFFFFFFFFF << self.bits_id
        if id & mask > 0:
            raise ValueError("id out of range that limited by bits_id")
        nonce = struct.unpack(">Q", os.urandom(8))[0]
        data, nonce = self.merge(id, nonce)
        data = self.rc4(data)
        data = list(struct.pack(">Q", nonce))[len(data) - 8:] + data
        data = array.array('B', data).tobytes()
        mask = 0xFFFFFFFFFFFFFFFF >> (64 - self.bits_target)
        data = struct.unpack(">Q", data)[0] & mask
        return self.encode(data)

    def decrypt(self, code):
        data = self.decode(code)
        mask = 0xFFFFFFFFFFFFFFFF >> (64 - self.bits_encrypt)
        data = list(struct.pack(">Q", data & mask))[-int(self.bits_encrypt / 8):]
        data = self.rc4(data)
        return self.parse(data)


if __name__ == "__main__":
    us = UniqueStringID("hello")
    code = us.encrypt(1234)
    print(code)
    id = us.decrypt(code)
    print(id)
