#!/bin/python3
import os
import nfc
import time
import threading
import binascii
import hashlib
import ctypes
import logging
from typing import TypeAlias, Union
import csv

PermitList: TypeAlias = tuple[tuple[bytes, str, str, bytes]]
term_flag = False
timer_flag = False

def on_connect(tag):
    timeout = 0.1

    # Polling System Code 0xFE00
    tag.idm, tag.pmm = tag.polling(0xFE00)
    time.sleep(timeout)
    idm = binascii.hexlify(tag.idm)
    pmm = binascii.hexlify(tag.pmm)

    # Read first block in ServiceCode 0x1A8B
    service = 0x1A8B
    sc = nfc.tag.tt3.ServiceCode(service >> 6 ,service & 0x3f)
    bc = nfc.tag.tt3.BlockCode(0)
    block = tag.read_without_encryption([sc],[bc])
    student_number = str(block[2:9], encoding='utf-8')

    # verify
    print('Verify NFC Tag as following:')
    print('IDM: ', idm, ', StudentNumber:', '\"' + student_number + '\"', ', PAM_USER:', '\"' + (os.getenv('PAM_USER') if os.getenv('PAM_USER') is not None else 'None') + '\"')
    authenticate(idm, student_number)

def authenticate(idm: bytes, student_number: str):
    global timer_flag
    auth_flag = False
    permit_list = get_permit_list()
    if permit_list is None:
        print('Failed Authentication')
        exit(1)
    for reserved_idm, reserved_sn, reserved_pam_user, salt in permit_list:
        legi_idm = verify_idm(idm, reserved_idm, salt)
        legi_stn = verify_student_number(student_number, reserved_sn)
        legi_pam_user = check_PAM_USER(reserved_pam_user)
        print('Verify IDM           : ', legi_idm)
        print('Verify StudentNumber : ', legi_stn)
        print('Verify PAM_USER      : ', legi_pam_user)
        if legi_pam_user and (legi_idm and legi_stn):
            auth_flag = True
            break
    if auth_flag:
        print('Success Authentication')
        timer_flag = True
        exit(0)
    else:
        print('Failed Authentication')
        timer_flag = True
        exit(1)

def get_permit_list(file: str = '/etc/security/permit_student_card.csv') -> Union[PermitList, None]:
    permit_list: PermintList = []
    try:
        with open(file, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                permit_list.append((bytes(row[0], encoding='utf-8'), str(row[1]), str(row[2]), bytes(row[3], encoding='utf-8')))
    except FileNotFoundError:
        print('FileNotFoundError:', file, 'is not found.')
        return None
    print(permit_list)
    return permit_list

def verify_idm(idm: bytes, reserved_idm: bytes, salt: bytes) -> bool:
    return True if bytes(hashlib.sha256(salt + idm).hexdigest(), encoding='utf-8') == reserved_idm else False

def verify_student_number(student_number: str, reserved_stn: str) -> bool:
    return True if student_number == reserved_stn else False

def check_PAM_USER(reserved_pam_user: str) -> bool:
    return True if os.getenv('PAM_USER') == reserved_pam_user else False

def timeout(sleep: int=5):
    global term_flag
    global timer_flag
    count = 0
    while not timer_flag and (count < sleep):
        time.sleep(0.5)
        count += 0.5
    term_flag = True


if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG)
    print('PAM_student_number start...')
    threading.Thread(target=timeout).start()
    clf = nfc.ContactlessFrontend("usb:054c:06c3")
    tag = clf.connect(rdwr={'on-connect': on_connect}, terminate=lambda: term_flag)
    if tag == None:
        print('Failed Authentication')
        exit(1)

