import os
import gzip
import json
import random
import binascii

from pathlib import Path
from Crypto.Cipher import AES
from functools import lru_cache

@lru_cache(maxsize=1)
def _load_dword():
    filename = "dword.json"
    filepath = Path(__file__).parent / "data" / filename
    if not os.path.exists(filepath):
        raise FileNotFoundError(filename)
    with open(filepath, "r") as f:
        return json.load(f)


class TTEncrypt:

    __content = []
    __content_raw = []

    CF = 0
    begining = [0x74, 0x63, 0x05, 0x10, 0, 0]
    list_9C8 = []

    @property
    def dword_0(self):
        return _load_dword()["dword_0"]

    @property
    def dword_1(self):
        return _load_dword()["dword_1"]

    @property
    def dword_2(self):
        return _load_dword()["dword_2"]

    @property
    def dword_3(self):
        return _load_dword()["dword_3"]

    @property
    def dword_4(self):
        return _load_dword()["dword_4"]

    @property
    def dword_5(self):
        return _load_dword()["dword_5"]

    @property
    def dword_6(self):
        return _load_dword()["dword_6"]

    @property
    def dword_7(self):
        return _load_dword()["dword_7"]

    @property
    def dword_8(self):
        return _load_dword()["dword_8"]

    @property
    def dword_9(self):
        return _load_dword()["dword_9"]

    @property
    def LIST_6B0(self):
        return _load_dword()["LIST_6B0"]

    @property
    def ord_list(self):
        return _load_dword()["ord_list"]

    @property
    def rodata(self):
        return _load_dword()["rodata"]

    def encrypt(self, data):
        headers = [31, 139, 8, 0, 0, 0, 0, 0, 0, 0]
        data = list(data)
        self.setData(data)
        for i in range(len(headers)):
            self.__content[i] = headers[i]
        list_0B0 = self.calculate(self.list_9C8) + self.ord_list
        list_5D8 = self.calculate(list_0B0)
        list_378 = []
        list_740 = []
        for i in range(0x10):
            list_378.append(list_5D8[i])
        list_378Array = self.dump_list(list_378)
        for i in range(0x10, 0x20):
            list_740.append(list_5D8[i])
        list_8D8 = self.calculate(self.__content)
        list_AB0 = list_8D8 + self.__content
        list_AB0List = self.convertLongList(list_AB0)
        differ = 0x10 - len(list_AB0) % 0x10
        for i in range(differ):
            list_AB0List.append(differ)
        list_AB0 = list_AB0List
        list_55C = self.hex_CF8(list_378Array)
        final_list = self.hex_0A2(list_AB0, list_740, list_55C)
        final_list = (self.begining + self.list_9C8) + final_list
        final_list = self.changeLongArrayTobytes(final_list)
        return bytes(i % 256 for i in final_list)

    def decrypt(self, data):
        data = list(data)
        self.setData(data)
        self.__content = self.__content_raw[38:]
        self.list_9C8 = self.__content_raw[6:38]
        self.__content = self.changeByteArrayToLong(self.__content)
        list_0B0 = self.calculate(self.list_9C8) + self.ord_list
        list_5D8 = self.calculate(list_0B0)
        list_378 = []
        list_740 = []
        for i in range(0x10):
            list_378.append(list_5D8[i])
        list_378Array = self.dump_list(list_378)
        for i in range(0x10, 0x20):
            list_740.append(list_5D8[i])
        key_longs = self.hex_list(list_378Array)
        decrypted = self.aes_decrypt(bytes(key_longs), bytes(self.__content))
        decryptedByteArray = ([0] * 16) + list(decrypted)
        toDecompress = decryptedByteArray[64:]
        result = gzip.decompress(bytes(toDecompress))
        res = bytes(result).decode()
        return res

    def aes_decrypt(self, secretKey, encoded):
        initVector = encoded[0:16]
        data = encoded[16:]
        decryptor = AES.new(secretKey, AES.MODE_CBC, initVector)
        decoded = decryptor.decrypt(data)
        return decoded[: -decoded[-1]]

    def bytearray_decode(self, arrays):
        out = []
        for d in arrays:
            out.append(chr(d))
        return "".join(out)

    def changeLongArrayTobytes(self, array):
        result = []
        for i in range(len(array)):
            if array[i] > 127:
                result.append(array[i] - 256)
            else:
                result.append(array[i])
        return result

    def hex_0A2(self, content, list_740, list_55C):
        result = []
        l55cl = len(list_55C)
        lens = len(content)
        end = lens // 16
        for i in range(end):
            for j in range(16):
                list_740[j] = list_740[j] ^ content[16 * i + j]
            tmp_list = self.dump_list(list_740)
            R6 = tmp_list[3]
            LR = tmp_list[0]
            R8 = tmp_list[1]
            R12 = tmp_list[2]
            R5 = list_55C[0]
            R4 = list_55C[1]
            R1 = list_55C[2]
            R2 = list_55C[3]
            R11 = 0
            v_334 = 0
            R2 = R2 ^ R6
            v_33C = R2
            R1 = R1 ^ R12
            v_338 = R1
            R4 = R4 ^ R8
            R12 = R5 ^ LR
            for j in range(5):
                R3 = v_33C
                R9 = R4
                R0 = int(self.UBFX(R12, 0x10, 8))
                R1 = R3 >> 0x18
                R1 = self.dword_6[R1]
                R0 = self.dword_7[R0]
                R0 = R0 ^ R1
                R1 = int(self.UBFX(R4, 8, 8))
                R8 = v_338
                R1 = self.dword_8[R1]
                LR = list_55C[8 * j + 6]
                R0 = R0 ^ R1
                R1 = int(self.UTFX(R8))
                R1 = self.dword_9[R1]
                R0 = R0 ^ R1
                R1 = list_55C[8 * j + 4]
                v_334 = R1
                R1 = list_55C[8 * j + 5]
                v_330 = R1
                R1 = list_55C[8 * j + 7]
                R11 = R0 ^ R1
                R1 = int(self.UBFX(R3, 0x10, 8))
                R0 = R8 >> 24
                R0 = self.dword_6[R0]
                R1 = self.dword_7[R1]
                R0 = R0 ^ R1
                R1 = int(self.UBFX(R12, 8, 8))
                R1 = self.dword_8[R1]
                R0 = R0 ^ R1
                R1 = int(self.UTFX(R9))
                R1 = self.dword_9[R1]
                R0 = R0 ^ R1
                R1 = int(self.UBFX(R8, 0x10, 8))
                R6 = R0 ^ LR
                R0 = R9 >> 24
                R0 = self.dword_6[R0]
                R1 = self.dword_7[R1]
                R0 = R0 ^ R1
                R1 = int(self.UBFX(R3, 8, 8))
                R1 = self.dword_8[R1]
                R0 = R0 ^ R1
                R1 = int(self.UTFX(R12))
                R1 = self.dword_9[R1]
                R0 = R0 ^ R1
                R1 = v_330
                LR = R0 ^ R1
                R0 = int(self.UTFX(R3))
                R0 = self.dword_9[R0]
                R4 = R12 >> 24
                R1 = int(self.UBFX(R8, 8, 8))
                R4 = self.dword_6[R4]
                R5 = int(self.UBFX(R9, 16, 8))
                R1 = self.dword_8[R1]
                R5 = self.dword_7[R5]
                R5 = R5 ^ R4
                R1 = R1 ^ R5
                R0 = R0 ^ R1
                R1 = v_334
                R1 = R1 ^ R0
                R0 = R1 >> 0x18
                v_334 = R0
                if j == 4:
                    break
                else:
                    R4 = int(self.UBFX(R1, 16, 8))
                    R5 = R11 >> 24
                    R10 = R6
                    R5 = self.dword_6[R5]
                    R4 = self.dword_7[R4]
                    R5 = R5 ^ R4
                    R4 = int(self.UBFX(LR, 8, 8))
                    R4 = self.dword_8[R4]
                    R5 = R5 ^ R4
                    R4 = int(self.UTFX(R10))
                    R4 = self.dword_9[R4]
                    R5 = R5 ^ R4
                    R4 = list_55C[8 * j + 11]
                    R0 = R5 ^ R4
                    v_33C = R0
                    R4 = int(self.UBFX(R11, 16, 8))
                    R5 = R10 >> 24
                    R5 = self.dword_6[R5]
                    R4 = self.dword_7[R4]
                    R5 = R5 ^ R4
                    R4 = int(self.UBFX(R1, 8, 8))
                    R0 = list_55C[8 * j + 9]
                    R9 = list_55C[8 * j + 8]
                    R1 = int(self.UTFX(R1))
                    R4 = self.dword_8[R4]
                    R1 = self.dword_9[R1]
                    R5 = R5 ^ R4
                    R4 = int(self.UTFX(LR))
                    R4 = self.dword_9[R4]
                    R5 = R5 ^ R4
                    R4 = list_55C[8 * j + 10]
                    R4 = R4 ^ R5
                    v_338 = R4
                    R5 = int(self.UBFX(R10, 16, 8))
                    R4 = LR >> 24
                    R4 = self.dword_6[R4]
                    R5 = self.dword_7[R5]
                    R4 = R4 ^ R5
                    R5 = int(self.UBFX(R11, 8, 8))
                    R5 = self.dword_8[R5]
                    R4 = R4 ^ R5
                    R1 = R1 ^ R4
                    R4 = R1 ^ R0
                    R0 = v_334
                    R1 = int(self.UBFX(LR, 16, 8))
                    R5 = int(self.UBFX(R10, 8, 8))
                    R0 = self.dword_6[R0]
                    R1 = self.dword_7[R1]
                    R5 = self.dword_8[R5]
                    R0 = R0 ^ R1
                    R1 = int(self.UTFX(R11))
                    R1 = self.dword_9[R1]
                    R0 = R0 ^ R5
                    R0 = R0 ^ R1
                    R12 = R0 ^ R9
            R2 = R11 >> 24
            R3 = int(self.UBFX(R1, 16, 8))
            R10 = R6
            R0 = R10 >> 24
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "000000", 10, 16))
            R9 = R10
            R3 = self.dword_0[R3]
            R3 = int(self.parseLong(self.toHex(R3) + "0000", 10, 16))
            R0 = self.dword_0[R0]
            R0 = int(self.parseLong(self.toHex(R0) + "000000", 10, 16))
            R2 = R2 ^ R3
            v_350 = R2
            R2 = int(self.UBFX(R11, 0x10, 8))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "0000", 10, 16))
            R0 = R0 ^ R2
            R2 = int(self.UBFX(R1, 8, 8))
            R1 = int(self.UTFX(R1))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "00", 10, 16))
            R1 = self.dword_0[R1]
            R0 = R0 ^ R2
            R2 = int(self.UTFX(LR))
            R2 = self.dword_0[R2]
            R12 = R0 ^ R2
            R0 = list_55C[l55cl - 2]
            R10 = list_55C[l55cl - 3]
            R12 = R12 ^ R0
            R2 = list_55C[l55cl - 1]
            R0 = LR >> 24
            v_34C = R2
            R2 = int(self.UBFX(R9, 0x10, 8))
            R0 = self.dword_0[R0]
            R0 = int(self.parseLong(self.toHex(R0) + "000000", 10, 16))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "0000", 10, 16))
            R0 = R0 ^ R2
            R2 = int(self.UBFX(R11, 8, 8))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "00", 10, 16))
            R0 = R0 ^ R2
            R0 = R0 ^ R1
            R1 = R0 ^ R10
            R0 = v_334
            R2 = int(self.UBFX(LR, 0x10, 8))
            R0 = self.dword_0[R0]
            R0 = int(self.parseLong(self.toHex(R0) + "000000", 10, 16))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "0000", 10, 16))
            R0 = R0 ^ R2
            R2 = int(self.UBFX(R9, 8, 8))
            R2 = self.dword_0[R2]
            R2 = int(self.parseLong(self.toHex(R2) + "00", 10, 16))
            R0 = R0 ^ R2
            R2 = int(self.UTFX(R11))
            R2 = self.dword_0[R2]
            R0 = R0 ^ R2
            R2 = int(self.UTFX(R9))
            R2 = self.dword_0[R2]
            R3 = int(self.UBFX(LR, 8, 8))
            R3 = self.dword_0[R3]
            R3 = int(self.parseLong(self.toHex(R3) + "00", 10, 16))
            R5 = v_350
            R6 = list_55C[l55cl - 4]
            R3 = R3 ^ R5
            R2 = R2 ^ R3
            R3 = v_34C
            R0 = R0 ^ R6
            R2 = R2 ^ R3
            list_740 = self.hex_list([R0, R1, R12, R2])
            result = result + list_740
        return result

    def calculate(self, content):
        hex_6A8 = 0
        tmp_list = []
        length = len(content)
        list_6B0 = self.LIST_6B0.copy()
        for item in content:
            tmp_list.append(item)
        divisible = length % 0x80
        tmp = 0x80 - divisible
        if tmp > 0x11:
            tmp_list.append(0x80)
            for i in range(tmp - 0x11):
                tmp_list.append(0)
            for j in range(16):
                tmp_list.append(0)
        else:
            tmp_list.append(128)

            for i in range(128 - 16 + tmp + 1):
                tmp_list.append(0)
            for j in range(16):
                tmp_list.append(0)
        tmp_list_size = len(tmp_list)
        d = tmp_list_size // 0x80
        for i in range(tmp_list_size // 0x80):
            if (tmp_list_size // 128 - 1) == i:
                ending = self.handle_ending(hex_6A8, divisible)
                for j in range(8):
                    index = tmp_list_size - j - 1
                    tmp_list[index] = ending[7 - j]
            param_list = []
            for j in range(32):
                tmpss = ""
                for k in range(4):
                    tmp_string = self.toHex(tmp_list[0x80 * i + 4 * j + k])
                    if len(tmp_string) < 2:
                        tmp_string = "0" + tmp_string
                    tmpss = tmpss + tmp_string
                param_list.append(int(self.parseLong(tmpss, 10, 16)))
            list_3B8 = self.hex_27E(param_list)
            list_6B0 = self.hex_30A(list_6B0, list_3B8)
            hex_6A8 += 0x400
        list_8D8 = self.hex_C52(list_6B0)
        return list_8D8

    def convertLongList(self, content):
        if len(content) == 0:
            return []
        result = []
        for i in content:
            result.append(i)
        return result

    def dump_list(self, content):
        size = len(content)
        ssize = size // 4
        result = []
        for index in range(ssize):
            tmp_string = ""
            for j in range(4):
                tmp = self.toHex(content[4 * index + j])
                if len(tmp) < 2:
                    tmp = "0" + tmp

                tmp_string = tmp_string + tmp
            i = int(self.parseLong(tmp_string, 10, 16))
            result.append(int(i))
        return result

    def hex_CF8(self, param_list):
        list_388 = []
        list_378 = param_list
        for i in range(0xA):
            R3 = list_378[0]
            R8 = list_378[1]
            R9 = list_378[2]
            R5 = list_378[3]
            R6 = int(self.UBFX(R5, 8, 8))
            R6 = self.dword_0[R6]
            R6 = int(self.parseLong(self.toHex(R6) + "0000", 10, 16))
            R4 = int(self.UBFX(R5, 0x10, 8))
            R11 = self.dword_1[i]
            R4 = self.dword_0[R4]
            R4 = int(self.parseLong(self.toHex(R4) + "000000", 10, 16))
            R3 = R3 ^ R4
            R4 = int(self.UTFX(R5))
            R3 = R3 ^ R6
            R4 = self.dword_0[R4]
            R4 = int(self.parseLong(self.toHex(R4) + "00", 10, 16))
            R3 = R3 ^ R4
            R4 = R5 >> 24
            R4 = self.dword_0[R4]
            R3 = R3 ^ R4
            R3 = R3 ^ R11
            R2 = R8 ^ R3
            R4 = R9 ^ R2
            R5 = R5 ^ R4
            list_378 = [R3, R2, R4, R5]
            list_388 = list_388 + list_378
        l388l = len(list_388)
        list_478 = []
        for i in range(0x9):
            R5 = list_388[l388l - 8 - 4 * i]
            R4 = int(self.UBFX(R5, 0x10, 8))
            R6 = R5 >> 0x18
            R6 = self.dword_2[R6]
            R4 = self.dword_3[R4]
            R6 = R6 ^ R4
            R4 = int(self.UBFX(R5, 8, 8))
            R5 = int(self.UTFX(R5))
            R4 = self.dword_4[R4]
            R5 = self.dword_5[R5]
            R6 = R6 ^ R4
            R6 = R6 ^ R5
            list_478.append(R6)
            R6 = list_388[l388l - 7 - 4 * i]
            R1 = int(self.UBFX(R6, 0x10, 8))
            R4 = R6 >> 0x18
            R4 = self.dword_2[R4]
            R1 = self.dword_3[R1]
            R1 = R1 ^ R4
            R4 = int(self.UBFX(R6, 8, 8))
            R4 = self.dword_4[R4]
            R1 = R1 ^ R4
            R4 = int(self.UTFX(R6))
            R4 = self.dword_5[R4]
            R1 = R1 ^ R4
            list_478.append(R1)
            R1 = list_388[l388l - 6 - 4 * i]
            R6 = int(self.UBFX(R1, 0x10, 8))
            R4 = R1 >> 0x18
            R4 = self.dword_2[R4]
            R6 = self.dword_3[R6]
            R4 = R4 ^ R6
            R6 = int(self.UBFX(R1, 8, 8))
            R1 = int(self.UTFX(R1))
            R6 = self.dword_4[R6]
            R1 = self.dword_5[R1]
            R4 = R4 ^ R6
            R1 = R1 ^ R4
            list_478.append(R1)
            R0 = list_388[l388l - 5 - 4 * i]
            R1 = int(self.UTFX(R0))
            R4 = int(self.UBFX(R0, 8, 8))
            R6 = R0 >> 0x18
            R0 = int(self.UBFX(R0, 0x10, 8))
            R6 = self.dword_2[R6]
            R0 = self.dword_3[R0]
            R4 = self.dword_4[R4]
            R1 = self.dword_5[R1]
            R0 = R0 ^ R6
            R0 = R0 ^ R4
            R0 = R0 ^ R1
            list_478.append(R0)
        list_468 = param_list + list_388
        return list_468

    def handle_ending(self, num, r0):
        s = self.toHex(num)
        r1 = None
        r2 = None
        if len(s) <= 8:
            r1 = num
            r2 = 0
        else:
            num_str = self.toHex(num)
            length = len(num)
            r1 = self.parseLong(num_str[: length - 8], 10, 16)
            r2 = self.parseLong(num_str[2 : length - 8], 10, 16)
        r1 = self.ADDS(r1, r0 << 3)
        r2 = self.ADC(r2, r0 >> 29)
        a = self.hex_list([r2, r1])
        return self.hex_list([r2, r1])

    def UTFX(self, num):
        tmp_string = self.toBinaryString(num)
        start = len(tmp_string) - 8
        return self.parseLong(tmp_string[start:], 10, 2)

    def hex_27E(self, param_list):
        r6 = param_list[0]
        r8 = param_list[1]
        for i in range(0x40):
            r0 = param_list[2 * i + 0x1C]
            r5 = param_list[2 * i + 0x1D]
            r4 = self.LSRS(r0, 0x13)
            r3 = self.LSRS(r0, 0x1D)
            lr = r4 | self.check(r5) << 13
            r4 = self.LSLS(r0, 3)
            r4 = r4 | self.check(r5) >> 29
            r3 = r3 | self.check(r5) << 3
            r4 = r4 ^ self.check(r0) >> 6
            lr = lr ^ r4
            r4 = self.LSRS(r5, 6)
            r4 = r4 | self.check(r0) << 26
            r9 = r3 ^ r4
            r4 = self.LSRS(r5, 0x13)
            r0 = r4 | self.check(r0) << 13
            r10 = param_list[2 * i + 0x12]
            r3 = param_list[2 * i + 0x13]
            r5 = param_list[2 * i + 0x2]
            r4 = param_list[2 * i + 0x3]
            r0 = r0 ^ r9
            r3 = self.ADDS(r3, r8)
            r6 = self.ADC(r6, r10)
            r8 = self.ADDS(r3, r0)
            lr = self.ADC(lr, r6)
            r6 = self.LSRS(r4, 7)
            r3 = self.LSRS(r4, 8)
            r6 = r6 | self.check(r5) << 25
            r3 = r3 | self.check(r5) << 24
            r3 = int(self.EORS(r3, r6))
            r6 = self.LSRS(r5, 1)
            r0 = int(self.RRX(r4))
            r0 = int(self.EORS(r0, r3))
            r3 = r6 | self.check(r4) << 31
            r6 = self.LSRS(r5, 8)
            r0 = int(self.ADDS(r0, r8))
            r6 = r6 | self.check(r4) << 24
            r8 = r4
            r6 = r6 ^ self.check(r5) >> 7
            r3 = r3 ^ r6
            r6 = r5
            r3 = self.ADC(r3, lr)
            param_list = param_list + [r3, r0]
        return param_list  # WORKED

    def hex_30A(self, param_list, list_3B8):
        v_3A0 = param_list[7]
        v_3A4 = param_list[6]
        v_374 = param_list[5]
        v_378 = param_list[4]
        LR = param_list[0]
        R12 = param_list[1]
        v_39C = param_list[2]
        v_398 = param_list[3]
        v_3AC = param_list[11]
        v_3A8 = param_list[10]
        R9 = param_list[12]
        R10 = param_list[13]
        R5 = param_list[9]
        R8 = param_list[8]
        R4 = param_list[15]
        R6 = param_list[14]
        for index in range(10):
            v_384 = R5
            R3 = self.rodata[0x10 * index]
            R1 = self.rodata[0x10 * index + 2]
            R2 = self.rodata[0x10 * index + 1]
            R3 = self.ADDS(R3, R6)
            R6 = self.check(R8) >> 14
            v_390 = R1
            R6 = R6 | self.check(R5) << 18
            R1 = self.rodata[0x10 * index + 3]
            R0 = self.rodata[0x10 * index + 4]
            v_36C = R0
            R0 = self.ADC(R2, R4)
            R2 = self.LSRS(R5, 0x12)
            R4 = self.LSRS(R5, 0xE)
            R2 = R2 | self.check(R8) << 14
            R4 = R4 | self.check(R8) << 18
            R2 = self.EORS(R2, R4)
            R4 = self.LSLS(R5, 0x17)
            R4 = R4 | self.check(R8) >> 9
            v_38C = R1
            R2 = self.EORS(R2, R4)
            R4 = self.check(R8) >> 18
            R4 = R4 | self.check(R5) << 14
            R6 = self.EORS(R6, R4)
            R4 = self.LSRS(R5, 9)
            R4 = R4 | self.check(R8) << 23
            v_354 = R8
            R6 = self.EORS(R6, R4)
            R3 = self.ADDS(R3, R6)
            R0 = self.ADCS(R0, R2)
            R2 = list_3B8[0x10 * index + 1]
            R2 = self.ADDS(R2, R3)
            R3 = list_3B8[0x10 * index + 3]
            R6 = list_3B8[0x10 * index]
            v_358 = R10
            R6 = self.ADCS(R6, R0)
            R0 = v_3AC
            v_360 = R3
            R0 = R0 ^ R10
            R3 = list_3B8[0x10 * index + 2]
            R0 = self.ANDS(R0, R5)
            R1 = list_3B8[0x10 * index + 5]
            R4 = R0 ^ R10
            R0 = v_3A8
            v_364 = R1
            R0 = R0 ^ R9
            R1 = v_374
            R0 = R0 & R8
            R8 = v_39C
            R0 = R0 ^ R9
            v_35C = R3
            R10 = self.ADDS(R2, R0)
            R0 = v_398
            R11 = self.ADC(R6, R4)
            R3 = v_378
            R2 = R0 | R12
            R6 = R0 & R12
            R2 = self.ANDS(R2, R1)
            R1 = R0
            R2 = self.ORRS(R2, R6)
            R6 = R8 | LR
            R6 = self.ANDS(R6, R3)
            R3 = R8 & LR
            R3 = self.ORRS(R3, R6)
            R6 = self.check(R12) << 30
            R0 = self.check(R12) >> 28
            R6 = R6 | self.check(LR) >> 2
            R0 = R0 | self.check(LR) << 4
            R4 = self.check(LR) >> 28
            R0 = self.EORS(R0, R6)
            R6 = self.check(R12) << 25
            R6 = R6 | self.check(LR) >> 7
            R4 = R4 | self.check(R12) << 4
            R0 = self.EORS(R0, R6)
            R6 = self.check(R12) >> 2
            R6 = R6 | self.check(LR) << 30
            R3 = self.ADDS(R3, R10)
            R6 = R6 ^ R4
            R4 = self.check(R12) >> 7
            R4 = R4 | self.check(LR) << 25
            R2 = self.ADC(R2, R11)
            R6 = self.EORS(R6, R4)
            v_37C = R12
            R5 = self.ADDS(R3, R6)
            R6 = self.ADC(R2, R0)
            R0 = R6 | R12
            R2 = R6 & R12
            R0 = self.ANDS(R0, R1)
            R3 = self.LSRS(R6, 0x1C)
            R0 = self.ORRS(R0, R2)
            R2 = self.LSLS(R6, 0x1E)
            R2 = R2 | self.check(R5) >> 2
            R3 = R3 | self.check(R5) << 4
            R2 = self.EORS(R2, R3)
            R3 = self.LSLS(R6, 0x19)
            R3 = R3 | self.check(R5) >> 7
            R4 = self.LSRS(R5, 0x1C)
            R3 = self.EORS(R3, R2)
            R2 = self.LSRS(R6, 2)
            R2 = R2 | self.check(R5) << 30
            R4 = R4 | self.check(R6) << 4
            R2 = self.EORS(R2, R4)
            R4 = self.LSRS(R6, 7)
            R4 = R4 | self.check(R5) << 25
            R12 = R6
            R2 = self.EORS(R2, R4)
            R4 = R5 | LR
            R4 = R4 & R8
            R6 = R5 & LR
            R4 = self.ORRS(R4, R6)
            v_388 = R5
            R5 = self.ADDS(R2, R4)
            R0 = self.ADCS(R0, R3)
            v_398 = R1
            R4 = R9
            v_350 = R0
            R0 = v_3A4
            R1 = v_3A0
            v_380 = LR
            LR = self.ADDS(R0, R10)
            R9 = self.ADC(R1, R11)
            R0 = v_3AC
            R6 = self.check(LR) >> 14
            R1 = v_384
            R3 = self.check(R9) >> 18
            R2 = self.check(R9) >> 14
            R3 = R3 | self.check(LR) << 14
            R2 = R2 | self.check(LR) << 18
            R2 = self.EORS(R2, R3)
            R3 = self.check(R9) << 23
            R3 = R3 | self.check(LR) >> 9
            R6 = R6 | self.check(R9) << 18
            R2 = self.EORS(R2, R3)
            R3 = self.check(LR) >> 18
            R3 = R3 | self.check(R9) << 14
            v_39C = R8
            R3 = self.EORS(R3, R6)
            R6 = self.check(R9) >> 9
            R6 = R6 | self.check(LR) << 23
            R8 = v_354
            R3 = self.EORS(R3, R6)
            R6 = R0 ^ R1
            R6 = R6 & R9
            v_370 = R12
            R6 = self.EORS(R6, R0)
            R0 = v_3A8
            R1 = R0 ^ R8
            R1 = R1 & LR
            R1 = self.EORS(R1, R0)
            R0 = v_358
            R1 = self.ADDS(R1, R4)
            R6 = self.ADCS(R6, R0)
            R0 = v_390
            R1 = self.ADDS(R1, R0)
            R0 = v_38C
            R6 = self.ADCS(R6, R0)
            R0 = v_360
            R1 = self.ADDS(R1, R0)
            R0 = v_35C
            R6 = self.ADCS(R6, R0)
            R1 = self.ADDS(R1, R3)
            R3 = self.ADC(R6, R2)
            R2 = v_350
            R0 = self.ADDS(R5, R1)
            R5 = v_37C
            R4 = self.ADC(R2, R3)
            v_390 = R4
            R2 = R4 | R12
            R6 = R4 & R12
            R2 = self.ANDS(R2, R5)
            R5 = self.LSRS(R4, 0x1C)
            R10 = R2 | R6
            R2 = self.LSLS(R4, 0x1E)
            R2 = R2 | self.check(R0) >> 2
            R5 = R5 | self.check(R0) << 4
            R2 = self.EORS(R2, R5)
            R5 = self.LSLS(R4, 0x19)
            R5 = R5 | self.check(R0) >> 7
            R6 = self.LSRS(R0, 0x1C)
            R12 = R2 ^ R5
            R2 = self.LSRS(R4, 2)
            R2 = R2 | self.check(R0) << 30
            R6 = R6 | self.check(R4) << 4
            R2 = self.EORS(R2, R6)
            R6 = self.LSRS(R4, 7)
            R4 = v_388
            R6 = R6 | self.check(R0) << 25
            R5 = v_380
            R2 = self.EORS(R2, R6)
            R6 = R0 | R4
            R4 = self.ANDS(R4, R0)
            R6 = self.ANDS(R6, R5)
            v_38C = R0
            R4 = self.ORRS(R4, R6)
            R6 = LR ^ R8
            R0 = self.ADDS(R2, R4)
            v_3A4 = R0
            R0 = self.ADC(R12, R10)
            v_3A0 = R0
            R0 = v_378
            R10 = self.ADDS(R1, R0)
            R0 = v_374
            R6 = R6 & R10
            R1 = self.ADC(R3, R0)
            R5 = self.check(R10) >> 14
            R0 = v_384
            R6 = R6 ^ R8
            R3 = self.LSRS(R1, 0x12)
            R4 = self.LSRS(R1, 0xE)
            R3 = R3 | self.check(R10) << 14
            R4 = R4 | self.check(R10) << 18
            R3 = self.EORS(R3, R4)
            R4 = self.LSLS(R1, 0x17)
            R4 = R4 | self.check(R10) >> 9
            R5 = R5 | self.check(R1) << 18
            R11 = R3 ^ R4
            R3 = self.check(R10) >> 18
            R3 = R3 | self.check(R1) << 14
            v_378 = R1
            R3 = self.EORS(R3, R5)
            R5 = self.LSRS(R1, 9)
            R5 = R5 | self.check(R10) << 23
            R3 = self.EORS(R3, R5)
            R5 = R9 ^ R0
            R5 = self.ANDS(R5, R1)
            R1 = v_3A8
            R5 = self.EORS(R5, R0)
            R0 = v_36C
            R4 = self.ADDS(R0, R1)
            R2 = self.rodata[0x10 * index + 5]
            R0 = v_3AC
            R2 = self.ADCS(R2, R0)
            R0 = v_364
            R4 = self.ADDS(R4, R0)
            R12 = list_3B8[0x10 * index + 4]
            R0 = v_3A4
            R2 = self.ADC(R2, R12)
            R6 = self.ADDS(R6, R4)
            R2 = self.ADCS(R2, R5)
            R3 = self.ADDS(R3, R6)
            R11 = self.ADC(R11, R2)
            R1 = self.ADDS(R0, R3)
            R0 = v_3A0
            R6 = v_390
            R4 = self.check(R1) >> 28
            R0 = self.ADC(R0, R11)
            R5 = v_370
            R2 = R0 | R6
            R6 = self.ANDS(R6, R0)
            R2 = self.ANDS(R2, R5)
            R5 = self.LSRS(R0, 0x1C)
            R12 = R2 | R6
            R6 = self.LSLS(R0, 0x1E)
            R6 = R6 | self.check(R1) >> 2
            R5 = R5 | self.check(R1) << 4
            R6 = self.EORS(R6, R5)
            R5 = self.LSLS(R0, 0x19)
            R5 = R5 | self.check(R1) >> 7
            R4 = R4 | self.check(R0) << 4
            R6 = self.EORS(R6, R5)
            R5 = self.LSRS(R0, 2)
            R5 = R5 | self.check(R1) << 30
            v_3AC = R0
            R5 = self.EORS(R5, R4)
            R4 = self.LSRS(R0, 7)
            R0 = v_38C
            R4 = R4 | self.check(R1) << 25
            R2 = v_388
            R5 = self.EORS(R5, R4)
            R4 = R1 | R0
            v_3A8 = R1
            R4 = self.ANDS(R4, R2)
            R2 = R1 & R0
            R2 = self.ORRS(R2, R4)
            R0 = self.ADDS(R5, R2)
            v_3A4 = R0
            R0 = self.ADC(R6, R12)
            v_3A0 = R0
            R0 = v_39C
            R2 = v_398
            R0 = self.ADDS(R0, R3)
            v_39C = R0
            R11 = self.ADC(R11, R2)
            R4 = self.LSRS(R0, 0xE)
            R3 = self.check(R11) >> 18
            R6 = self.check(R11) >> 14
            R3 = R3 | self.check(R0) << 14
            R6 = R6 | self.check(R0) << 18
            R3 = self.EORS(R3, R6)
            R6 = self.check(R11) << 23
            R6 = R6 | self.check(R0) >> 9
            R4 = R4 | self.check(R11) << 18
            R1 = self.EORS(R3, R6)
            R6 = self.LSRS(R0, 0x12)
            R6 = R6 | self.check(R11) << 14
            R3 = R10 ^ LR
            R6 = self.EORS(R6, R4)
            R4 = self.check(R11) >> 9
            R3 = self.ANDS(R3, R0)
            R4 = R4 | self.check(R0) << 23
            R5 = R6 ^ R4
            v_398 = R1
            R3 = R3 ^ LR
            R1 = v_378
            R6 = self.rodata[0x10 * index + 6]
            R12 = self.rodata[0x10 * index + 7]
            R4 = R1 ^ R9
            R0 = v_384
            R6 = self.ADDS(R6, R8)
            R4 = R4 & R11
            R12 = self.ADC(R12, R0)
            R4 = R4 ^ R9
            R8 = list_3B8[0x10 * index + 7]
            R2 = list_3B8[0x10 * index + 6]
            R6 = self.ADDS(R6, R8)
            R0 = v_398
            R2 = self.ADC(R2, R12)
            R3 = self.ADDS(R3, R6)
            R2 = self.ADCS(R2, R4)
            R6 = self.ADDS(R3, R5)
            R12 = self.ADC(R2, R0)
            R0 = v_3A4
            R4 = v_390
            R1 = self.ADDS(R0, R6)
            R0 = v_3A0
            v_384 = R1
            R5 = self.ADC(R0, R12)
            R0 = v_3AC
            R8 = self.check(R1) >> 28
            R2 = R5 | R0
            R3 = R8 | self.check(R5) << 4
            R2 = self.ANDS(R2, R4)
            R4 = R5 & R0
            R0 = R2 | R4
            R4 = self.LSLS(R5, 0x1E)
            R2 = self.LSRS(R5, 0x1C)
            R4 = R4 | self.check(R1) >> 2
            R2 = R2 | self.check(R1) << 4
            v_3A0 = R0
            R2 = self.EORS(R2, R4)
            R4 = self.LSLS(R5, 0x19)
            R4 = R4 | self.check(R1) >> 7
            R0 = v_3A8
            R2 = self.EORS(R2, R4)
            R4 = self.LSRS(R5, 2)
            R4 = R4 | self.check(R1) << 30
            R8 = R5
            R3 = self.EORS(R3, R4)
            R4 = self.LSRS(R5, 7)
            R4 = R4 | self.check(R1) << 25
            R5 = v_38C
            R3 = self.EORS(R3, R4)
            R4 = R1 | R0
            R4 = self.ANDS(R4, R5)
            R5 = R1 & R0
            R4 = self.ORRS(R4, R5)
            v_36C = R8
            R0 = self.ADDS(R3, R4)
            v_3A4 = R0
            R0 = v_3A0
            R0 = self.ADCS(R0, R2)
            v_3A0 = R0
            R0 = v_380
            R2 = v_37C
            R0 = self.ADDS(R0, R6)
            R5 = self.ADC(R12, R2)
            v_37C = R5
            R4 = self.LSRS(R0, 0xE)
            v_380 = R0
            R2 = self.LSRS(R5, 0x12)
            R3 = self.LSRS(R5, 0xE)
            R2 = R2 | self.check(R0) << 14
            R3 = R3 | self.check(R0) << 18
            R2 = self.EORS(R2, R3)
            R3 = self.LSLS(R5, 0x17)
            R3 = R3 | self.check(R0) >> 9
            R4 = R4 | self.check(R5) << 18
            R1 = R2 ^ R3
            R3 = self.LSRS(R0, 0x12)
            R3 = R3 | self.check(R5) << 14
            v_398 = R1
            R3 = self.EORS(R3, R4)
            R4 = self.LSRS(R5, 9)
            R1 = v_378
            R4 = R4 | self.check(R0) << 23
            R12 = R3 ^ R4
            R3 = list_3B8[0x10 * index + 9]
            R4 = R11 ^ R1
            R4 = self.ANDS(R4, R5)
            R4 = self.EORS(R4, R1)
            R1 = v_39C
            R5 = R1 ^ R10
            R5 = self.ANDS(R5, R0)
            R5 = R5 ^ R10
            R2 = self.rodata[0x10 * index + 8]
            R0 = self.ADDS(R2, LR)
            R2 = self.rodata[0x10 * index + 9]
            R2 = self.ADC(R2, R9)
            R0 = self.ADDS(R0, R3)
            R3 = list_3B8[0x10 * index + 8]
            R2 = self.ADCS(R2, R3)
            R0 = self.ADDS(R0, R5)
            R2 = self.ADCS(R2, R4)
            R1 = self.ADDS(R0, R12)
            R0 = v_398
            R3 = v_3AC
            R4 = self.ADC(R2, R0)
            R0 = v_3A4
            R6 = self.ADDS(R0, R1)
            R0 = v_3A0
            v_3A4 = R6
            R0 = self.ADCS(R0, R4)
            v_3A0 = R0
            R2 = R0 | R8
            R2 = self.ANDS(R2, R3)
            R3 = R0 & R8
            LR = R2 | R3
            R8 = R6
            R3 = self.LSLS(R0, 0x1E)
            R5 = self.LSRS(R0, 0x1C)
            R3 = R3 | self.check(R8) >> 2
            R5 = R5 | self.check(R8) << 4
            R3 = self.EORS(R3, R5)
            R5 = self.LSLS(R0, 0x19)
            R5 = R5 | self.check(R8) >> 7
            R2 = self.check(R8) >> 28
            R12 = R3 ^ R5
            R5 = self.LSRS(R0, 2)
            R5 = R5 | self.check(R8) << 30
            R2 = R2 | self.check(R0) << 4
            R2 = self.EORS(R2, R5)
            R5 = self.LSRS(R0, 7)
            R3 = v_384
            R5 = R5 | self.check(R8) << 25
            R6 = v_3A8
            R2 = self.EORS(R2, R5)
            R5 = R8 | R3
            R5 = self.ANDS(R5, R6)
            R6 = R8 & R3
            R5 = self.ORRS(R5, R6)
            R0 = self.ADDS(R2, R5)
            v_398 = R0
            R2 = v_388
            R12 = self.ADC(R12, LR)
            R0 = v_370
            R3 = self.ADDS(R1, R2)
            R1 = v_380
            R8 = self.ADC(R4, R0)
            R0 = R3
            R2 = self.check(R8) >> 18
            R3 = self.check(R8) >> 14
            R2 = R2 | self.check(R0) << 14
            R3 = R3 | self.check(R0) << 18
            R2 = self.EORS(R2, R3)
            R3 = self.check(R8) << 23
            R3 = R3 | self.check(R0) >> 9
            R4 = self.LSRS(R0, 0xE)
            LR = R2 ^ R3
            R3 = self.LSRS(R0, 0x12)
            R3 = R3 | self.check(R8) << 14
            R4 = R4 | self.check(R8) << 18
            R3 = self.EORS(R3, R4)
            R4 = self.check(R8) >> 9
            R4 = R4 | self.check(R0) << 23
            R2 = R0
            R0 = v_37C
            R3 = self.EORS(R3, R4)
            v_388 = R2
            R4 = R0 ^ R11
            R0 = v_39C
            R4 = R4 & R8
            R5 = R1 ^ R0
            R4 = R4 ^ R11
            R5 = self.ANDS(R5, R2)
            R5 = self.EORS(R5, R0)
            R6 = self.rodata[0x10 * index + 10]
            R1 = self.ADDS(R6, R10)
            R6 = self.rodata[0x10 * index + 11]
            R0 = v_378
            R6 = self.ADCS(R6, R0)
            R2 = list_3B8[0x10 * index + 11]
            R1 = self.ADDS(R1, R2)
            R2 = list_3B8[0x10 * index + 10]
            R0 = v_398
            R2 = self.ADCS(R2, R6)
            R1 = self.ADDS(R1, R5)
            R2 = self.ADCS(R2, R4)
            R1 = self.ADDS(R1, R3)
            R4 = self.ADC(R2, LR)
            R6 = v_3A0
            R0 = self.ADDS(R0, R1)
            R9 = self.ADC(R12, R4)
            R3 = v_36C
            R2 = R9 | R6
            R5 = self.check(R9) >> 28
            v_374 = R9
            R2 = self.ANDS(R2, R3)
            R3 = R9 & R6
            R10 = R2 | R3
            R3 = self.check(R9) << 30
            R3 = R3 | self.check(R0) >> 2
            R5 = R5 | self.check(R0) << 4
            R3 = self.EORS(R3, R5)
            R5 = self.check(R9) << 25
            R5 = R5 | self.check(R0) >> 7
            R6 = self.LSRS(R0, 0x1C)
            R12 = R3 ^ R5
            R5 = self.check(R9) >> 2
            R5 = R5 | self.check(R0) << 30
            R6 = R6 | self.check(R9) << 4
            R5 = self.EORS(R5, R6)
            R6 = self.check(R9) >> 7
            R3 = v_3A4
            R6 = R6 | self.check(R0) << 25
            R2 = v_384
            R5 = self.EORS(R5, R6)
            R6 = R0 | R3
            R6 = self.ANDS(R6, R2)
            R2 = R0 & R3
            R2 = R2 | R6
            R2 = self.ADDS(R2, R5)
            v_398 = R2
            R2 = self.ADC(R12, R10)
            v_378 = R2
            R2 = v_38C
            R12 = self.ADDS(R1, R2)
            R1 = v_390
            LR = self.ADC(R4, R1)
            R4 = self.check(R12) >> 14
            R1 = self.check(LR) >> 18
            R2 = self.check(LR) >> 14
            R1 = R1 | self.check(R12) << 14
            R2 = R2 | self.check(R12) << 18
            R1 = self.EORS(R1, R2)
            R2 = self.check(LR) << 23
            R2 = R2 | self.check(R12) >> 9
            R4 = R4 | self.check(LR) << 18
            R1 = self.EORS(R1, R2)
            R2 = self.check(R12) >> 18
            R2 = R2 | self.check(LR) << 14
            v_390 = R1
            R2 = self.EORS(R2, R4)
            R4 = self.check(LR) >> 9
            R1 = v_37C
            R4 = R4 | self.check(R12) << 23
            R10 = R2 ^ R4
            R2 = v_388
            R4 = R8 ^ R1
            R4 = R4 & LR
            R4 = self.EORS(R4, R1)
            R1 = v_380
            R5 = R2 ^ R1
            R2 = v_39C
            R5 = R5 & R12
            R5 = self.EORS(R5, R1)
            R6 = self.rodata[0x10 * index + 12]
            R3 = self.rodata[0x10 * index + 13]
            R6 = self.ADDS(R6, R2)
            R3 = self.ADC(R3, R11)
            R1 = list_3B8[0x10 * index + 13]
            R1 = self.ADDS(R1, R6)
            R6 = list_3B8[0x10 * index + 12]
            R3 = self.ADCS(R3, R6)
            R1 = self.ADDS(R1, R5)
            R3 = self.ADCS(R3, R4)
            R5 = self.ADDS(R1, R10)
            R1 = v_390
            R2 = self.ADC(R3, R1)
            R1 = v_398
            R3 = v_3A0
            R10 = self.ADDS(R1, R5)
            R1 = v_378
            v_378 = R0
            R11 = self.ADC(R1, R2)
            R6 = self.check(R10) >> 28
            R1 = R11 | R9
            v_398 = R11
            R1 = self.ANDS(R1, R3)
            R3 = R11 & R9
            R9 = R1 | R3
            R3 = self.check(R11) << 30
            R4 = self.check(R11) >> 28
            R3 = R3 | self.check(R10) >> 2
            R4 = R4 | self.check(R10) << 4
            R6 = R6 | self.check(R11) << 4
            R3 = self.EORS(R3, R4)
            R4 = self.check(R11) << 25
            R4 = R4 | self.check(R10) >> 7
            R1 = v_3A4
            R3 = self.EORS(R3, R4)
            R4 = self.check(R11) >> 2
            R4 = R4 | self.check(R10) << 30
            v_39C = R10
            R4 = self.EORS(R4, R6)
            R6 = self.check(R11) >> 7
            R6 = R6 | self.check(R10) << 25
            R4 = self.EORS(R4, R6)
            R6 = R10 | R0
            R6 = self.ANDS(R6, R1)
            R1 = R10 & R0
            R1 = self.ORRS(R1, R6)
            R10 = LR
            R0 = self.ADDS(R4, R1)
            v_390 = R0
            R0 = self.ADC(R3, R9)
            v_38C = R0
            R0 = v_3A8
            R9 = R12
            R4 = self.ADDS(R5, R0)
            R0 = v_3AC
            v_3A8 = R4
            R0 = self.ADCS(R0, R2)
            R3 = self.LSRS(R4, 0xE)
            v_3AC = R0
            R1 = self.LSRS(R0, 0x12)
            R2 = self.LSRS(R0, 0xE)
            R1 = R1 | self.check(R4) << 14
            R2 = R2 | self.check(R4) << 18
            R1 = self.EORS(R1, R2)
            R2 = self.LSLS(R0, 0x17)
            R2 = R2 | self.check(R4) >> 9
            R3 = R3 | self.check(R0) << 18
            R11 = R1 ^ R2
            R2 = self.LSRS(R4, 0x12)
            R2 = R2 | self.check(R0) << 14
            R2 = self.EORS(R2, R3)
            R3 = self.LSRS(R0, 9)
            R3 = R3 | self.check(R4) << 23
            R2 = self.EORS(R2, R3)
            R3 = LR ^ R8
            R3 = self.ANDS(R3, R0)
            R0 = v_388
            LR = R3 ^ R8
            R5 = R12 ^ R0
            R5 = self.ANDS(R5, R4)
            R3 = R0
            R5 = self.EORS(R5, R0)
            R4 = self.rodata[0x10 * index + 14]
            R6 = self.rodata[0x10 * index + 15]
            R0 = v_380
            R4 = self.ADDS(R4, R0)
            R0 = v_37C
            R6 = self.ADCS(R6, R0)
            R0 = list_3B8[0x10 * index + 14]
            R1 = list_3B8[0x10 * index + 15]
            R1 = self.ADDS(R1, R4)
            R0 = self.ADCS(R0, R6)
            R1 = self.ADDS(R1, R5)
            R0 = self.ADC(R0, LR)
            R1 = self.ADDS(R1, R2)
            R2 = v_390
            R0 = self.ADC(R0, R11)
            R4 = R8
            LR = self.ADDS(R2, R1)
            R2 = v_38C
            R6 = R3
            R12 = self.ADC(R2, R0)
            R2 = v_384
            R8 = self.ADDS(R1, R2)
            R2 = v_36C
            R5 = self.ADC(R0, R2)
        list_638 = [
            self.check(LR),
            self.check(R12),
            self.check(v_39C),
            self.check(v_398),
            self.check(v_378),
            self.check(v_374),
            self.check(v_3A4),
            self.check(v_3A0),
            self.check(R8),
            self.check(R5),
            self.check(v_3A8),
            self.check(v_3AC),
            self.check(R9),
            self.check(R10),
            self.check(R6),
            self.check(R4),
        ]
        for i in range(8):
            R0 = param_list[2 * i]
            R1 = param_list[2 * i + 1]
            R0 = self.ADDS(R0, list_638[2 * i])
            R1 = self.ADCS(R1, list_638[2 * i + 1])
            param_list[2 * i] = R0
            param_list[2 * i + 1] = R1
        return param_list

    def hex_C52(self, list_6B0):
        list_8D8 = []
        for i in range(8):
            tmp = self.hex_list([list_6B0[2 * i + 1], list_6B0[2 * i]])
            list_8D8 = list_8D8 + tmp
        return list_8D8

    def toHex(self, num):
        return format(int(num), "x")

    def check(self, tmp):
        ss = ""
        if tmp < 0:
            ss = self.toHex(4294967296 + int(tmp))
        else:
            ss = self.toHex(tmp)
        if len(ss) > 8:
            size = len(ss)
            start = size - 8
            ss = ss[start:]
            tmp = int(self.parseLong(ss, 10, 16))
        return tmp

    def ADDS(self, a, b):
        c = self.check(a) + self.check(b)
        if len(self.toHex(c)) > 8:
            self.CF = 1
        else:
            self.CF = 0
        result = self.check(c)
        return result

    def ANDS(self, a, b):
        return self.check(a & b)

    def EORS(self, a, b):
        return self.check(a ^ b)

    def ADC(self, a, b):
        c = self.check(a) + self.check(b)
        d = self.check(c + self.CF)  # type: ignore
        return d

    def ADCS(self, a, b):
        c = self.check(a) + self.check(b)
        d = self.check(c + self.CF)  # type: ignore
        if len(self.toHex(c)) > 8:
            self.CF = 1
        else:
            self.CF = 0
        return d

    def LSLS(self, num, k):
        result = self.bin_type(num)
        self.CF = result[k - 1]
        return self.check(self.check(num) << k)

    def LSRS(self, num, k):
        result = self.bin_type(num)
        self.CF = result[len(result) - k]
        return self.check(self.check(num) >> k)

    def ORRS(self, a, b):
        return self.check(a | b)

    def RRX(self, num):
        result = self.bin_type(num)
        lenght = len(result)
        s = str(self.CF) + result[: lenght - 1 - 0]
        return self.parseLong(s, 10, 2)

    def bin_type(self, num):
        result = ""
        num = self.check(num)
        lst = self.toBinaryString(num)
        for i in range(32):
            if i < len(lst):
                result += str(lst[i])
            else:
                result = "0" + result
        return result

    def UBFX(self, num, lsb, width):
        tmp_string = self.toBinaryString(num)
        while len(tmp_string) < 32:
            tmp_string = "0" + tmp_string
        lens = len(tmp_string)
        start = lens - lsb - width
        end = start - lsb
        return int(self.parseLong(tmp_string[start : end - start], 10, 2))

    def UFTX(self, num):
        tmp_string = self.toBinaryString(num)
        start = len(tmp_string) - 8
        return self.parseLong(tmp_string[start:], 10, 2)

    def toBinaryString(self, num):
        return "{0:b}".format(num)

    def setData(self, data):
        self.__content_raw = data
        self.__content = data
        self.list_9C8 = self.hex_9C8()

    def hex_9C8(self):
        result = []
        for i in range(32):
            result.append(self.choice(0, 0x100))
        return result

    def choice(self, start, end):
        return int(random.uniform(0, 1) * (end + 1 - start) + start)

    def s2b(self, data):
        arr = []
        for i in range(len(data)):
            arr.append(data[i])
        return arr

    def hex_list(self, content):
        result = []
        for value in content:
            tmp = self.toHex(value)
            while len(tmp) < 8:
                tmp = "0" + tmp
            for i in range(4):
                start = 2 * i
                end = 2 * i + 2
                ss = tmp[start:end]
                result.append(int(self.parseLong(ss, 10, 16)))
        return result

    def parseLong(self, num, to_base=10, from_base=10):
        if isinstance(num, str):
            n = int(num, from_base)
        else:
            n = int(num)
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if n < to_base:
            return alphabet[n]
        else:
            return self.parseLong(n // to_base, to_base) + alphabet[n % to_base]

    def byteArray2str(self, b):
        return binascii.hexlify(bytes(b)).decode()

    def changeByteArrayToLong(self, bytes):
        result = []
        for byte in bytes:
            if byte < 0:
                result.append(byte + 256)
            else:
                result.append(byte)
        return result
