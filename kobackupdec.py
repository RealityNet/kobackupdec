#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Huawei KoBackup backups decryptor.
#
# Version History
# - 20200607: merged empty CheckMsg, update folder_to_media_type by @realSnoopy
# - 20200406: merged pull by @lp4n6, related to files and folders permissions
# - 20200405: added Python minor version check and note (thanks @lp4n6)
# - 2020test: rewritten to handle v9 and v10 backups
# - 20200107: merged pull by @lp4n6, fixed current version
# - 20191113: fixed double folder creation error
# - 20190729: first public release
# - 20190729: first public release
#
# Note: it needs Python version >= 3.7
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
import enum
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

VERSION = '20200607'

# Disabling check on doc strings and naming convention.
# pylint: disable=C0111,C0103

# --- DecryptMaterial ---------------------------------------------------------

class DecryptMaterial:

    def __init__(self, type_name):
        self._type_name = type_name
        self._name = None
        self._encMsgV3 = None
        self._iv = None
        self._path = None
        self._records_num = None
        self._copy_file_path = None

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
    def records_num(self):
        return self._records_num

    @records_num.setter
    def records_num(self, value_string):
        self._records_num = value_string

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
    def copy_file_path(self):
        return self._copy_file_path

    @copy_file_path.setter
    def copy_file_path(self, value_string):
        self._copy_file_path = value_string

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value_string):
        if value_string:
            self._path = value_string
        else:
            logging.error('empty file path!')

    def do_check(self):
        if self._name and (self._encMsgV3 or self._iv):
            return True
        return False

    def dump(self):
        dump = 'NAME: {}, TYPE: {}, '.format(self._name, self._type_name)
        if self._path:
            dump += 'PATH: {}, '.format(self._path)
        if self._copy_file_path:
            dump += 'COPY_FILEPATH: {}, '.format(self._copy_file_path)
        if self._records_num:
            dump += 'RECORDS_NUM: {}'.format(self._records_num)
        # Not reported: self._encMsgV3, self._iv
        dump += '\n'
        return dump


# --- Decryptor ---------------------------------------------------------------

class Decryptor:
    '''It provides algo and key derivations to decrypt files.'''

    count = 5000
    dklen = 32

    def __init__(self, password):
        '''Initialize the object by setting a password.'''
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
    def password(self):
        return self._upwd

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
        if salt:
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
        else:
            logging.warning('Empty CheckMsg! Cannot check backup password!')
            logging.warning('Assuming the provided password is correct...')
            self._good = True

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

# --- DecryptInfo -------------------------------------------------------------

class DecryptInfo:
    '''It provides the information and keys to decrypt files.'''

    class info_type(enum.Enum):
        FILE = 1
        MEDIA = 2
        MULTIMEDIA = 3
        SYSTEM_DATA = 4
        SYSTEM_DATA_FOLDER = 5

    def __init__(self):
        self._decryptor = None
        self._file_info = {}
        self._media_info = {}
        self._multimedia_file = {}
        self._system_data_info = {}
        self._system_data_folder_info = {}

    def search_decrypt_material(self, key):
        assert key
        decrypt_material = None
        if key in self._file_info:
            decrypt_material = self._file_info[key]
        elif key in self._media_info:
            decrypt_material = self._media_info[key]
        elif key in self._multimedia_file:
            decrypt_material = self._multimedia_file[key]
        elif key in self._system_data_info:
            decrypt_material = self._system_data_info[key]
        elif key in self._system_data_folder_info:
            decrypt_material = self._system_data_folder_info[key]
        else:
            pass
        return decrypt_material

    def get_decrypt_material(self, key, di_type, search=False):
        assert key
        assert isinstance(di_type, DecryptInfo.info_type)
        decrypt_material = None
        logging.debug('searching key [%s] of %s', key, di_type)
        if di_type is DecryptInfo.info_type.FILE:
            if key in self._file_info:
                decrypt_material = self._file_info[key]
        elif di_type is DecryptInfo.info_type.MEDIA:
            if key in self._media_info:
                decrypt_material = self._media_info[key]
        elif di_type is DecryptInfo.info_type.MULTIMEDIA:
            if key in self._multimedia_file:
                decrypt_material = self._multimedia_file[key]
        elif di_type is DecryptInfo.info_type.SYSTEM_DATA:
            if key in self._system_data_info:
                decrypt_material = self._system_data_info[key]
        elif di_type is DecryptInfo.info_type.SYSTEM_DATA_FOLDER:
            if key in self._system_data_folder_info:
                decrypt_material = self._system_data_folder_info[key]
        else:
            logging.critical('Unknown decrypt info type %s', di_type)
            return None
        if decrypt_material is None:
            if search is True:
                logging.debug('unable to get [%s], trying on all types', key)
                decrypt_material = self.search_decrypt_material(key)
        if decrypt_material is None:
            logging.debug('unable to get [%s] in decrypt material!', key)
        else:
            logging.debug('decrypt info  [%s] found', key)
        return decrypt_material

    @property
    def decryptor(self):
        return self._decryptor

    @decryptor.setter
    def decryptor(self, new_decryptor):
        assert new_decryptor
        new_decryptor.crypto_init()
        if not new_decryptor.good:
            logging.warning('Setting a new decryptor which is not working!')
        self._decryptor = new_decryptor

    @property
    def has_media(self):
        '''Checks if media categories decryption info is provided.'''
        return bool(self._media_info)

    def add_file_info(self, decrypt_material):
        '''Add the decryption material for a BackupFileModuleInfo entry to the
           proper internal object.
        '''
        assert decrypt_material.type_name == 'BackupFileModuleInfo'
        if decrypt_material.name in self._file_info:
            logging.error('Duplicate file info, cannot insert %s',
                          decrypt_material.name)
            return
        self._file_info[decrypt_material.name] = decrypt_material

    def add_media_info(self, decrypt_material):
        '''Add the decryption material for a BackupFileModuleInfo_Media
           entry to the proper internal object.
        '''
        assert decrypt_material.type_name == 'BackupFileModuleInfo_Media'
        if decrypt_material.name in self._file_info:
            logging.error('Duplicate media info, cannot insert %s',
                          decrypt_material.name)
            return
        self._media_info[decrypt_material.name] = decrypt_material

    def add_multimedia_file(self, decrypt_material):
        '''Add the decryption material for a multimedia file
           entry to the proper internal object.
        '''
        assert decrypt_material.type_name == 'Multimedia'
        if decrypt_material.path in self._multimedia_file:
            logging.error('Duplicate multimedia file path, cannot insert %s',
                          decrypt_material.path)
            return
        # Note path is used for the key, not name.
        self._multimedia_file[decrypt_material.path] = decrypt_material

    def add_system_data_info(self, decrypt_material):
        '''Add the decryption material for a BackupFileModuleInfo_SystemData
           entry to the proper internal object. It handles the scenario where
           the entry is related to folders, double copying the material.
        '''
        assert decrypt_material.type_name == 'BackupFileModuleInfo_SystemData'
        name = decrypt_material.name
        if name in self._system_data_info:
            logging.error('Duplicated system data info, cannot insert %s',
                          decrypt_material.name)
            return
        self._system_data_info[decrypt_material.name] = decrypt_material
        copyfilepath = decrypt_material.copy_file_path
        if copyfilepath and copyfilepath.startswith('/'):
            if copyfilepath in self._system_data_folder_info:
                logging.error('Duplicated system data folder info, cannot '
                              'insert %s', copyfilepath)
            else:
                self._system_data_folder_info[copyfilepath] = decrypt_material

    def dump(self):
        dump = 'DecryptInfo dump ---\n'
        dump += 'password:{}, '.format(self._decryptor.password)
        dump += 'good:{}, '.format(self._decryptor.good)
        dump += 'has media:{}, '.format(self.has_media)
        dump += 'file info:{}, '.format(len(self._file_info))
        dump += 'media info:{}, '.format(len(self._media_info))
        dump += 'multimedia file:{}, '.format(len(self._multimedia_file))
        dump += 'system data info:{}, '.format(len(self._system_data_info))
        dump += 'system folder data info:{}\n'.format(len(
            self._system_data_folder_info))

        dump += 'DUMPING FILE INFO ITEMS\n'
        for _, ev in self._file_info.items():
            dump += ev.dump()
        dump += 'DUMPING MEDIA INFO ITEMS\n'
        for _, ev in self._media_info.items():
            dump += ev.dump()
        dump += 'DUMPING MULTIMEDIA FILE ITEMS\n'
        for _, ev in self._multimedia_file.items():
            dump += ev.dump()
        dump += 'DUMPING SYSTEM DATA INFO ITEMS\n'
        for _, ev in self._system_data_info.items():
            dump += ev.dump()
        dump += 'DUMPING SYSTEM DATA FOLDER INFO ITEMS\n'
        for _, ev in self._system_data_folder_info.items():
            dump += ev.dump()
        return dump

# --- xml_get_column_value ----------------------------------------------------

def xml_get_column_value(xml_node):
    '''Helper to get xml 'column' value.'''
    child = xml_node.firstChild
    column_value = None
    try:
        if child.tagName == 'value':
            if child.hasAttribute('String'):
                column_value = str(child.getAttribute('String'))
            elif child.hasAttribute('Integer'):
                column_value = int(child.getAttribute('Integer'))
            elif child.hasAttribute('Null'):
                column_value = None
            else:
                logging.warning('xml column value: unknown value attribute.')
        else:
            logging.warning('xml_get_column_value: entry has no values!')
    except:
        logging.warning('*exception*, xml_get_column_value, child: %s', child)

    return column_value

# --- parse_backup_files_type_info --------------------------------------------

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

# --- parse_backup_file_module_info -------------------------------------------

def parse_backup_file_module_info(xml_entry):
    decm = DecryptMaterial(xml_entry.getAttribute('table'))
    for entry in xml_entry.getElementsByTagName('column'):
        tag_name = entry.getAttribute('name')
        if tag_name == 'encMsgV3':
            decm.encMsgV3 = xml_get_column_value(entry)
        elif tag_name == 'name':
            decm.name = xml_get_column_value(entry)
        elif tag_name == 'copyFilePath':
            decm.copy_file_path = xml_get_column_value(entry)
        elif tag_name == 'checkMsgV3':
            # [TBR][TODO] Reverse this double sized checkMsgV3.
            pass

    if decm.do_check() is False:
        logging.warning('Decryption material checks failed for %s, type %s',
                        decm.name, decm.type_name)
    return decm

# --- parse_info_xml ----------------------------------------------------------

def parse_info_xml(filepath, password):
    '''Parses the info.xml backup file.
       Creates and returns a DecryptInfo object.
    '''
    logging.info('Parsing file %s', filepath.absolute())
    info_dom = None
    with filepath.open('r', encoding='utf-8') as info_xml:
        info_dom = xml.dom.minidom.parse(info_xml)

    if info_dom.firstChild.tagName != 'info.xml':
        logging.error('First tag should be \'info.xml\', not %s',
                      info_dom.firstChild.tagName)
        return None

    dec_info = DecryptInfo()

    for entry in info_dom.getElementsByTagName('row'):
        title = entry.getAttribute('table')
        if title == 'BackupFileModuleInfo':
            dec_info.add_file_info(parse_backup_file_module_info(entry))
        elif title == 'BackupFileModuleInfo_SystemData':
            dec_info.add_system_data_info(parse_backup_file_module_info(entry))
        elif title == 'BackupFileModuleInfo_Media':
            dec_info.add_media_info(parse_backup_file_module_info(entry))
        elif title == 'BackupFilesTypeInfo':
            logging.debug('Parsing BackupFilesTypeInfo')
            decryptor = Decryptor(password)
            parse_backup_files_type_info(decryptor, entry)
            dec_info.decryptor = decryptor
        elif title == 'BackupFileModuleInfo_Contact':
            logging.debug('Ignoring BackupFileModuleInfo_Contact entry')
        elif title == 'HeaderInfo':
            logging.debug('Ignoring HeaderInfo entry.')
        elif title == 'BackupFilePhoneInfo':
            logging.debug('Ignoring BackupFilePhoneInfo entry')
        elif title == 'BackupFileVersionInfo':
            logging.debug('Ignoring BackupFileVersionInfo entry')
        else:
            logging.warning('Unknown entry in info.xml: %s', title)

    return dec_info

# --- parse_generic_xml -------------------------------------------------------

def parse_generic_xml(xml_file_path, decrypt_info):
    '''Parses a generic XML file, which contain single media (video, documents,
       pictures, etc.) decryption material.
    '''
    xml_dom = None
    logging.info('parsing xml file %s', xml_file_path.name)

    with xml_file_path.open('r', encoding='utf-8') as xml_file:
        xml_dom = xml.dom.minidom.parse(xml_file)

    if xml_dom.firstChild.tagName != 'Multimedia':
        logging.error('First tag should be \'Multimedia\', not %s',
                      xml_dom.firstChild.tagName)
        return

    for entry in xml_dom.getElementsByTagName('File'):
        path = entry.getElementsByTagName('Path')[0].firstChild.data
        iv = entry.getElementsByTagName('Iv')[0].firstChild.data
        if path and iv:
            if os.name != 'nt':
                path = path.replace('\\', '/')
            decrypt_material = DecryptMaterial('Multimedia')
            decrypt_material.path = path.lstrip('\\').lstrip('/')
            decrypt_material.iv = iv
            decrypt_info.add_multimedia_file(decrypt_material)
        else:
            logging.warning('No path and/or iv for %s!', entry)

# --- tar_extract_win ---------------------------------------------------------

def tar_extract_win(tar_obj, dest_dir):
    win_illegal = ':<>|"?*\n'
    table = str.maketrans(win_illegal, '_' * len(win_illegal))
    for member in tar_obj.getmembers():
        if member.isdir():
            new_dir = dest_dir.joinpath(member.path.translate(table))
            new_dir.mkdir(parents=True, exist_ok=True)
        else:
            dest_file = dest_dir.joinpath(member.path.translate(table))
            try:
                with open(dest_file, "wb") as fout:
                    fout.write(tarfile.ExFileObject(tar_obj, member).read())
            except FileNotFoundError:
                logging.warning('unable to extract %s', dest_file)

# --- decrypt_entry -----------------------------------------------------------

def decrypt_entry(decrypt_info, entry, type_info, search=False):
    cleartext = None
    skey = entry.stem
    decrypt_material = decrypt_info.get_decrypt_material(skey, type_info,
                                                         search)
    if decrypt_material:
        cleartext = decrypt_info.decryptor.decrypt_package(
            decrypt_material, entry.read_bytes())
    else:
        logging.warning('entry %s has no decrypt material!', skey)
    return cleartext

# --- decrypt_files_in_root ---------------------------------------------------

def decrypt_files_in_root(decrypt_info, path_in, path_out):

    data_apk_dir = path_out.absolute().joinpath('data/app')
    data_app_dir = path_out.absolute().joinpath('data/data')
    #data_app_dir.mkdir(0o755, parents=True, exist_ok=True)
    data_unk_dir = path_out.absolute().joinpath('unknown')

    for entry in path_in.glob('*'):
        if entry.is_dir():
            continue
        cleartext = None
        extension = entry.suffix.lower()

        # XML files in the 'root' were already managed.
        if extension == '.xml':
            continue
        logging.info('working on %s', entry.name)

        if extension == '.apk':
            dest_file = data_apk_dir.joinpath(entry.name + '-1')
            dest_file.mkdir(0o755, parents=True, exist_ok=True)
            dest_file = dest_file.joinpath('base.apk')
            dest_file.write_bytes(entry.read_bytes())

        elif extension == '.db':
            cleartext = decrypt_entry(decrypt_info, entry,
                                      DecryptInfo.info_type.SYSTEM_DATA,
                                      search=True)
            if cleartext:
                dest_file = data_app_dir.joinpath(entry.name)
                dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
                dest_file.write_bytes(cleartext)
            else:
                logging.warning('unable to decrypt entry %s', entry.name)

        elif extension == '.tar':
            cleartext = decrypt_entry(decrypt_info, entry,
                                      DecryptInfo.info_type.FILE)
            if cleartext:
                with tarfile.open(fileobj=io.BytesIO(cleartext)) as tar_data:
                    if os.name == 'nt':
                        tar_extract_win(tar_data, data_app_dir)
                    else:
                        tar_data.extractall(path=data_app_dir)
            else:
                logging.warning('unable to decrypt entry %s', entry.name)

        else:
            logging.warning('entry %s unmanged, copying it', entry.name)
            dest_file = data_unk_dir.joinpath(entry.name)
            dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
            dest_file.write_bytes(entry.read_bytes())

# --- decrypt_files_in_folder -------------------------------------------------

def decrypt_files_in_folder(decrypt_info, folder, path_out):

    folder_to_media_type = {'movies': 'video', 'pictures': 'photo',
                            'audios': 'audio', }

    media_out_dir = path_out.absolute().joinpath('storage')
    media_unk_dir = path_out.absolute().joinpath('unknown')

    for entry in folder.glob('**/*'):
        if entry.is_dir():
            continue

        logging.info('working on [%s]', entry.name)
        extension = entry.suffix.lower()

        cleartext = None

        if extension == '.enc':
            skey = str(entry.relative_to(folder).with_suffix(''))
            decrypt_material = decrypt_info.get_decrypt_material(
                skey, DecryptInfo.info_type.MULTIMEDIA)
            if decrypt_material:
                cleartext = decrypt_info.decryptor.decrypt_file(
                    decrypt_material, entry.read_bytes())

            if cleartext and decrypt_material:
                tmp_path = decrypt_material.path.lstrip('/').lstrip('\\')
                dest_file = path_out.joinpath(tmp_path)
                dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
                dest_file.write_bytes(cleartext)
                continue

        decrypt_material = decrypt_info.get_decrypt_material(
            folder.name, DecryptInfo.info_type.MEDIA)
        if not decrypt_material:
            # Some folders share a common type even if with different names.
            if folder.name in folder_to_media_type:
                decrypt_material = decrypt_info.get_decrypt_material(
                    folder_to_media_type[folder.name],
                    DecryptInfo.info_type.MEDIA)
        if decrypt_material:
            cleartext = decrypt_info.decryptor.decrypt_package(
                decrypt_material, entry.read_bytes())
            if cleartext:
                dest_file = media_out_dir.joinpath(entry.relative_to(folder))
                dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
                dest_file.write_bytes(cleartext)
                continue

        skey = '/' +  str(entry.relative_to(folder).parent)
        decrypt_material = decrypt_info.get_decrypt_material(
            skey, DecryptInfo.info_type.SYSTEM_DATA_FOLDER)
        if decrypt_material:
            cleartext = decrypt_info.decryptor.decrypt_package(
                decrypt_material, entry.read_bytes())
            if cleartext:
                dest_file = media_out_dir.joinpath(entry.relative_to(folder))
                dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
                if entry.suffix.lower() == '.tar':
                    with tarfile.open(fileobj=io.BytesIO(cleartext)) as tdata:
                        if os.name == 'nt':
                            tar_extract_win(tdata, dest_file.parent)
                        else:
                            tdata.extractall(path=dest_file.parent)
                # Double copy here the tar and the extracted one, no overwrite.
                if dest_file.exists():
                    new_name = str(folder.name) + '_' + str(dest_file.name)
                    dest_file = dest_file.parent.joinpath(new_name)
                    dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
                dest_file.write_bytes(cleartext)
                continue

        if cleartext is None:
            logging.warning('decrypting [%s] failed, copying it', entry.name)
            dest_file = media_unk_dir.joinpath(entry.name)
            dest_file.parent.mkdir(0o755, parents=True, exist_ok=True)
            dest_file.write_bytes(entry.read_bytes())


# --- decrypt_backup ----------------------------------------------------------

def decrypt_backup(password, path_in, path_out):

    decrypt_info = parse_info_xml(path_in.joinpath('info.xml'), password)
    if not decrypt_info:
        logging.critical('failed to parse info.xml')
        return

    if not decrypt_info.decryptor.good:
        logging.critical('Decryptor checks failed. Unable to decrypt')
        return

    xml_files = path_in.glob('*.xml')
    for entry in xml_files:
        if entry.name != 'info.xml':
            parse_generic_xml(entry, decrypt_info)

    logging.debug(decrypt_info.dump())

    decrypt_files_in_root(decrypt_info, path_in, path_out)

    for entry in path_in.glob('*'):
        if entry.is_dir():
            decrypt_files_in_folder(decrypt_info, entry, path_out)

# --- decrypt_media -----------------------------------------------------------

def decrypt_media(password, path_in, path_out):

    # [TODO][TBR] Should parse media.db sqlite.

    decrypt_info = None
    subfolder = None
    for entry in path_in.glob('**/info.xml'):
        decrypt_info = parse_info_xml(entry, password)
        subfolder = entry.parent

    if decrypt_info is None or subfolder is None:
        logging.error('unable to find or parse info.xml in media folder!')
        return

    if not decrypt_info.decryptor.good:
        logging.critical('Decryptor checks failed. Unable to decrypt')
        return

    logging.debug(decrypt_info.dump())

    for entry in subfolder.glob('*'):
        if entry.is_dir():
            decrypt_files_in_folder(decrypt_info, entry, path_out)

# --- main --------------------------------------------------------------------

def main(password, backup_path_in, dest_path_out):

    logging.info('searching backup in [%s]', backup_path_in)

    files_folder = None
    if backup_path_in.joinpath('info.xml').exists():
        files_folder = backup_path_in
    else:
        if backup_path_in.joinpath('backupFiles1').is_dir():
            files_folder = backup_path_in.joinpath('backupFiles1')
            info_xml = next(files_folder.glob('**/info.xml'), None)
            if info_xml:
                files_folder = info_xml.parent
            else:
                logging.error('Unable to find info.xml in backupFiles1!')
                return
        else:
            logging.error('No backup1 folder nor info.xml file found!')
            return

    if files_folder:
        logging.info('got info.xml, going to decrypt backup files')
        decrypt_backup(password, files_folder, dest_path_out)

    media_folder = None
    if backup_path_in.joinpath('media').is_dir():
        logging.info('got media folder, going to decrypt media files')
        media_folder = backup_path_in.joinpath('media')
    else:
        logging.info('No media folder found.')

    if media_folder:
        decrypt_media(password, media_folder, dest_path_out)

    logging.info('setting all decrypted files to read-only')
    for entry in dest_path_out.glob('**/*'):
        # Set read-only permission if entry is a file.
        if os.path.isfile(entry):
            os.chmod(entry, 0o444)

        # *nix directories require execute permission to read/traverse
        elif os.path.isdir(entry):
            os.chmod(entry, 0o555)


# --- entry point and parameters checks ---------------------------------------

if __name__ == '__main__':

    if sys.version_info[0] < 3:
        sys.exit('Python 3 or a more recent version is required.')
    elif sys.version_info[1] < 7:
        sys.exit('Python 3.7 or a more recent version is required.')

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
    
    # Make directory with read and execute permission (=read and traverse)
    dest_path.mkdir(0o755,parents=True)

    main(user_password, backup_path, dest_path)
