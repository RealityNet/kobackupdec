#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Huawei KoBackup backups decryptor.
#
# Version History
# - 20191113: fixed double folder creation error
# - 20190729: first public release
#
# Released under MIT License
#
# Copyright (c) 2019 Francesco "dfirfpi" Picasso, Reality Net System Solutions
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
'''Huawei KoBackup decryptor.'''

import argparse
import binascii
import io
import logging
import os
import os.path
import pathlib
import sys
import tarfile
import xml.dom.minidom

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter

VERSION = '20190729'

# Disabling check on doc strings and naming convention.
# pylint: disable=C0111,C0103

# --- DecryptMaterial ---------------------------------------------------------

class DecryptMaterial:

    def __init__(self, type_name):
        self._type_name = type_name
        self._name = None
        self._encMsgV3 = None
        self._iv = None
        self._filepath = None

    @property
    def type_name(self):
        return self._type_name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value_string):
        if value_string:
            self._name = value_string
        else:
            logging.error('empty entry name!')

    @property
    def encMsgV3(self):
        return self._encMsgV3

    @encMsgV3.setter
    def encMsgV3(self, value_hex_string):
        if value_hex_string:
            self._encMsgV3 = binascii.unhexlify(value_hex_string)
            if len(self._encMsgV3) != 48:
                logging.error('encMsgV3 should be 48 bytes long!')

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, value_hex_string):
        if value_hex_string:
            self._iv = binascii.unhexlify(value_hex_string)
            if len(self._iv) != 16:
                logging.error('iv should be 16 bytes long!')

    @property
    def path(self):
        return self._filepath

    @path.setter
    def path(self, value_string):
        if value_string:
            self._filepath = value_string
        else:
            logging.error('empty file path!')

    def do_check(self):
        if self._name and (self._encMsgV3 or self._iv):
            return True
        return False

# --- Decryptor ---------------------------------------------------------------

class Decryptor:

    count = 5000
    dklen = 32

    def __init__(self, password):
        self._upwd = password
        self._good = False
        self._e_perbackupkey = None
        self._pwkey_salt = None
        self._type_attch = 0
        self._checkMsg = None
        self._bkey = None
        self._bkey_sha256 = None

    @property
    def good(self):
        return self._good

    @property
    def e_perbackupkey(self):
        return self._e_perbackupkey

    @e_perbackupkey.setter
    def e_perbackupkey(self, value_hex_string):
        if value_hex_string:
            self._e_perbackupkey = binascii.unhexlify(value_hex_string)
            if len(self._e_perbackupkey) != 48:
                logging.error('e_perbackupkey should be 48 bytes long!')

    @property
    def pwkey_salt(self):
        return self._pwkey_salt

    @pwkey_salt.setter
    def pwkey_salt(self, value_hex_string):
        if value_hex_string:
            self._pwkey_salt = binascii.unhexlify(value_hex_string)
            if len(self._pwkey_salt) != 32:
                logging.error('pwkey_salt should be 32 bytes long!')

    @property
    def type_attch(self):
        return self._type_attch

    @type_attch.setter
    def type_attch(self, value_int):
        self._type_attch = value_int

    @property
    def checkMsg(self):
        return self._checkMsg

    @checkMsg.setter
    def checkMsg(self, value_hex_string):
        if value_hex_string:
            self._checkMsg = binascii.unhexlify(value_hex_string)
            if len(self._checkMsg) != 64:
                logging.error('checkMsg should be 64 bytes long!')

    @staticmethod
    def prf(p, s):
        return HMAC.new(p, s, SHA256).digest()

    def __decrypt_bkey_v4(self):
        key_salt = self._pwkey_salt[:16]
        logging.debug('KEY_SALT[%s] = %s', len(key_salt),
                      binascii.hexlify(key_salt))

        key = PBKDF2(self._upwd, key_salt, Decryptor.dklen, Decryptor.count,
                     Decryptor.prf)
        logging.debug('KEY[%s] = %s', len(key), binascii.hexlify(key))

        nonce = self._pwkey_salt[16:]
        logging.debug('KEY NONCE[%s] = %s', len(nonce),
                      binascii.hexlify(nonce))

        cipher = AES.new(key, mode=AES.MODE_GCM, nonce=nonce)
        self._bkey = cipher.decrypt(self._e_perbackupkey)[:32]
        logging.debug('BKEY[%s] =   %s',
                      len(self._bkey), binascii.hexlify(self._bkey))

    def crypto_init(self):
        if self._good:
            logging.info('crypto_init: already done with success!')
            return

        if self._type_attch != 3:
            logging.error('crypto_init: type_attch *should be* 3!')
            return

        if self._e_perbackupkey and self._pwkey_salt:
            logging.debug('crypto_init: using version 4.')
            self.__decrypt_bkey_v4()
        else:
            logging.debug('crypto_init: using version 3.')
            self._bkey = self._upwd

        self._bkey_sha256 = SHA256.new(self._bkey).digest()[:16]
        logging.debug('SHA256(BKEY)[%s] = %s', len(self._bkey_sha256),
                      binascii.hexlify(self._bkey_sha256))

        salt = self._checkMsg[32:]
        logging.debug('SALT[%s] = %s', len(salt), binascii.hexlify(salt))

        res = PBKDF2(self._bkey, salt, Decryptor.dklen, Decryptor.count,
                     Decryptor.prf, hmac_hash_module=None)
        logging.debug('KEY check expected = %s',
                      binascii.hexlify(self._checkMsg[:32]))
        logging.debug('RESULT = %s', binascii.hexlify(res))

        if res == self._checkMsg[:32]:
            logging.info('OK, backup key is correct!')
            self._good = True
        else:
            logging.error('KO, backup key is wrong!')
            self._good = False

    def decrypt_package(self, dec_material, data):
        if not self._good:
            logging.warning('well, it is hard to decrypt with a wrong key.')

        if not dec_material.encMsgV3:
            logging.error('cannot decrypt with an empty encMsgV3!')
            return None

        salt = dec_material.encMsgV3[:32]
        counter_iv = dec_material.encMsgV3[32:]

        key = PBKDF2(self._bkey, salt, Decryptor.dklen, Decryptor.count,
                     Decryptor.prf, hmac_hash_module=None)

        counter_obj = Counter.new(128, initial_value=int.from_bytes(
            counter_iv, byteorder='big'), little_endian=False)

        decryptor = AES.new(key, mode=AES.MODE_CTR, counter=counter_obj)
        return decryptor.decrypt(data)

    def decrypt_file(self, dec_material, data):
        if not self._good:
            logging.warning('well, it is hard to decrypt with a wrong key.')

        if not dec_material.iv:
            logging.error('cannot decrypt with an empty iv!')
            return None

        counter_obj = Counter.new(
            128,
            initial_value=int.from_bytes(dec_material.iv, byteorder='big'),
            little_endian=False)

        decryptor = AES.new(
            self._bkey_sha256, mode=AES.MODE_CTR, counter=counter_obj)
        return decryptor.decrypt(data)

# --- info.xml ----------------------------------------------------------------

def xml_get_column_value(xml_node):
    child = xml_node.firstChild
    if child.tagName != 'value':
        logging.warning('xml_get_column_value: entry has no values!')
        return None

    if child.hasAttribute('Null'):
        return None
    if child.hasAttribute('String'):
        return str(child.getAttribute('String'))
    if child.hasAttribute('Integer'):
        return int(child.getAttribute('Integer'))

    logging.warning('xml_get_column_value: unknown value attribute.')
    return None

def parse_backup_files_type_info(decryptor, xml_entry):
    for entry in xml_entry.getElementsByTagName('column'):
        name = entry.getAttribute('name')
        if name == 'e_perbackupkey':
            decryptor.e_perbackupkey = xml_get_column_value(entry)
        elif name == 'pwkey_salt':
            decryptor.pwkey_salt = xml_get_column_value(entry)
        elif name == 'type_attch':
            decryptor.type_attch = xml_get_column_value(entry)
        elif name == 'checkMsg':
            decryptor.checkMsg = xml_get_column_value(entry)
    return decryptor

def ignore_entry(xml_entry):
    logging.debug('ignoring entry %s', xml_entry.getAttribute('table'))

def parse_backup_file_module_info(xml_entry):
    decm = DecryptMaterial(xml_entry.getAttribute('table'))
    for entry in xml_entry.getElementsByTagName('column'):
        tag_name = entry.getAttribute('name')
        if tag_name == 'encMsgV3':
            decm.encMsgV3 = xml_get_column_value(entry)
        elif tag_name == 'checkMsgV3':
            #TBR: reverse this double sized checkMsgV3.
            pass
        elif tag_name == 'name':
            decm.name = xml_get_column_value(entry)

    if decm.do_check() is False:
        decm = None
    return decm

info_xml_callbacks = {
    'HeaderInfo' : ignore_entry,
    'BackupFilePhoneInfo' : ignore_entry,
    'BackupFileVersionInfo' : ignore_entry,
    'BackupFileModuleInfo' : parse_backup_file_module_info,
    'BackupFileModuleInfo_Contact' : parse_backup_file_module_info,
    'BackupFileModuleInfo_Media' : parse_backup_file_module_info,
    'BackupFileModuleInfo_SystemData' : parse_backup_file_module_info
}

def parse_info_xml(filepath, decryptor, decrypt_material_dict):
    info_dom = None
    with filepath.open('r', encoding='utf-8') as info_xml:
        info_dom = xml.dom.minidom.parse(info_xml)

    if info_dom.firstChild.tagName != 'info.xml':
        logging.error('First tag should be \'info.xml\', not %s',
                      info_dom.firstChild.tagName)
        return None, None

    parent = filepath.parent

    for entry in info_dom.getElementsByTagName('row'):
        title = entry.getAttribute('table')
        if title == 'BackupFilesTypeInfo':
            decryptor = parse_backup_files_type_info(decryptor, entry)
        else:
            if title in info_xml_callbacks:
                dec_material = info_xml_callbacks[title](entry)
                if dec_material:
                    dkey = parent.joinpath(dec_material.name)
                    decrypt_material_dict[dkey] = dec_material
            else:
                logging.warning('Unknown entry in info.xml: %s', title)

    return decryptor, decrypt_material_dict

def parse_xml(filepath, decrypt_material_dict):
    xml_dom = None
    with filepath.open('r', encoding='utf-8') as xml_file:
        xml_dom = xml.dom.minidom.parse(xml_file)

    logging.debug('parsing xml file %s', filepath.name)

    parent = filepath.parent.joinpath(filepath.stem)

    for entry in xml_dom.getElementsByTagName('File'):
        path = entry.getElementsByTagName('Path')[0].firstChild.data
        iv = entry.getElementsByTagName('Iv')[0].firstChild.data
        if path and iv:
            dec_material = DecryptMaterial(filepath.stem)
            # XML files use Windows style path separator, backslash.
            if os.name != 'nt':
                path = path.replace('\\', '/')
            dec_material.path = path
            dec_material.iv = iv
            dkey = parent.joinpath(path.lstrip('/').lstrip('\\'))
            decrypt_material_dict[dkey] = dec_material

    return decrypt_material_dict

# --- tar_extract_win ---------------------------------------------------------

def tar_extract_win(tar_obj, dest_dir):
    win_illegal = ':<>|"?*\n'
    table = str.maketrans(win_illegal, '_' * len(win_illegal))
    for member in tar_obj.getmembers():
        if member.isdir():
            new_dir = dest_dir.joinpath(member.path.translate(table))
            new_dir.mkdir(exist_ok=True)
        else:
            dest_file = dest_dir.joinpath(member.path.translate(table))
            try:
                with open(dest_file, "wb") as fout:
                    fout.write(tarfile.ExFileObject(tar_obj, member).read())
            except FileNotFoundError:
                logging.error('unable to extract %s', dest_file)

# --- main --------------------------------------------------------------------

def main(password, backup_path_in, dest_path_out):

    xml_files = []
    apk_files = []
    tar_files = []
    enc_files = []
    db_files = []
    unk_files = []
    folders = []

    logging.info('getting files and folder from %s', backup_path_in)
    backup_all_files = backup_path_in.glob('**/*')
    for entry in backup_all_files:
        if entry.is_dir():
            folders.append(entry.absolute())
            continue
        extension = entry.suffix.lower()
        if extension == '.xml':
            xml_files.append(entry.absolute())
        elif extension == '.apk':
            apk_files.append(entry.absolute())
        elif extension == '.tar':
            tar_files.append(entry.absolute())
        elif extension == '.db':
            db_files.append(entry.absolute())
        elif extension == '.enc':
            enc_files.append(entry.absolute())
        else:
            unk_files.append(entry.absolute())

    decrypt_material_dict = {}
    decryptor = Decryptor(password)

    logging.info('parsing XML files...')
    for entry in xml_files:
        logging.info('parsing xml %s', entry.name)
        if entry.name.lower() == 'info.xml':
            decryptor, decrypt_material_dict = parse_info_xml(
                entry, decryptor, decrypt_material_dict)
        else:
            decrypt_material_dict = parse_xml(
                entry, decrypt_material_dict)

    decryptor.crypto_init()
    if decryptor.good is False:
        logging.critical('decryption key is not good...')
        return

    logging.info('copying apk to destination...')
    data_apk_dir = dest_path_out.absolute().joinpath('data/app')
    data_apk_dir.mkdir(parents=True)

    done_list = []
    for entry in apk_files:
        logging.info('working on %s', entry.name)
        dest_file = data_apk_dir.joinpath(entry.name + '-1')
        dest_file.mkdir(exist_ok=True)
        dest_file = dest_file.joinpath('base.apk')
        dest_file.write_bytes(entry.read_bytes())
        done_list.append(entry)

    for entry in done_list:
        apk_files.remove(entry)

    logging.info('decrypting and un-tar-ing packages to destination...')
    data_app_dir = dest_path_out.absolute().joinpath('data/data')
    data_app_dir.mkdir(parents=True)

    done_list = []
    for entry in tar_files:
        logging.info('working on %s', entry.name)
        cleartext = None
        skey = entry.absolute().with_suffix('')
        if skey in decrypt_material_dict:
            done_list.append(entry)
            cleartext = decryptor.decrypt_package(
                decrypt_material_dict[skey], entry.read_bytes())
        else:
            logging.warning('entry %s has no decrypt material!', skey)

        if cleartext:
            with tarfile.open(fileobj=io.BytesIO(cleartext)) as tar_data:
                if os.name == 'nt':
                    tar_extract_win(tar_data, data_app_dir)
                else:
                    tar_data.extractall(path=data_app_dir)

    for entry in done_list:
        tar_files.remove(entry)

    logging.info('decrypting database files to destination...')
    data_app_dir = dest_path_out.absolute().joinpath('db')
    data_app_dir.mkdir(parents=True)

    done_list = []
    for entry in db_files:
        logging.info('working on %s', entry.name)
        cleartext = None
        skey = entry.absolute().with_suffix('')
        if skey in decrypt_material_dict:
            done_list.append(entry)
            cleartext = decryptor.decrypt_package(
                decrypt_material_dict[skey], entry.read_bytes())
        else:
            logging.warning('entry %s has no decrypt material!', skey)

        if cleartext:
            dest_file = data_app_dir.joinpath(entry.name)
            dest_file.write_bytes(cleartext)

    for entry in done_list:
        db_files.remove(entry)

    logging.info('decrypting multimedia files to destination...')
    done_list = []
    for entry in enc_files:
        cleartext = None
        dec_material = None
        skey = entry.absolute().with_suffix('')
        if skey in decrypt_material_dict:
            done_list.append(entry)
            dec_material = decrypt_material_dict[skey]
            cleartext = decryptor.decrypt_file(
                dec_material, entry.read_bytes())
        else:
            logging.warning('entry %s has no decrypt material!', skey)

        if cleartext and dec_material:
            dest_file = dest_path_out.absolute()
            tmp_path = dec_material.path.lstrip('/').lstrip('\\')
            dest_file = dest_file.joinpath(tmp_path)
            dest_dir = dest_file.parent
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file.write_bytes(cleartext)

    for entry in done_list:
        enc_files.remove(entry)

    logging.info('copying unmanaged files to destination...')
    data_unk_dir = dest_path_out.absolute().joinpath('misc')
    data_unk_dir.mkdir(parents=True)

    done_list = []
    for entry in unk_files:
        common_path = os.path.commonpath([
            entry.absolute(), backup_path_in.absolute()])
        relative_path = str(entry.absolute()).replace(common_path, '')
        relative_path = relative_path.lstrip('/').lstrip('\\')
        dest_file = data_unk_dir.joinpath(relative_path)
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_bytes(entry.read_bytes())
        done_list.append(entry)

    for entry in done_list:
        unk_files.remove(entry)

    all_dest_files = dest_path_out.glob('**/*')
    for entry in all_dest_files:
        os.chmod(entry, 0o444)

    for entry in apk_files:
        logging.warning('APK file not handled: %s', entry.name)

    for entry in tar_files:
        logging.warning('TAR file not handled: %s', entry.name)

    for entry in db_files:
        logging.warning('DB file not handled: %s', entry.name)

    for entry in enc_files:
        logging.warning('ENC file not handled: %s', entry.name)

    for entry in unk_files:
        logging.warning('UNK file not handled: %s', entry.name)

# --- entry point and parameters checks ---------------------------------------

if __name__ == '__main__':

    if sys.version_info[0] < 3:
        sys.exit('Python 3 or a more recent version is required.')

    description = 'Huawei KoBackup decryptor version {}'.format(VERSION)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('password', help='user password for the backup')
    parser.add_argument('backup_path', help='backup folder')
    parser.add_argument('dest_path', help='decrypted backup folder')
    parser.add_argument('-v', '--verbose', action='count',
                        help='verbose level, -v to -vvv')
    args = parser.parse_args()

    log_level = logging.CRITICAL
    if not args.verbose:
        log_level = logging.ERROR
    elif args.verbose == 1:
        log_level = logging.WARNING
    elif args.verbose == 2:
        log_level = logging.INFO
    elif args.verbose >= 3:
        log_level = logging.DEBUG

    logging.basicConfig(level=log_level)

    user_password = args.password.encode('utf-8')

    backup_path = pathlib.Path(args.backup_path)
    if not backup_path.is_dir():
        sys.exit('Backup folder does not exist!')

    dest_path = pathlib.Path(args.dest_path)
    if dest_path.is_dir():
        sys.exit('Destination folder already exists!')
    dest_path.mkdir(parents=True)

    main(user_password, backup_path, dest_path)
