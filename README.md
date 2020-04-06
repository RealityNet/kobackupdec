# kobackupdec
Huawei backup decryptor

_This script is introduced by the blog post at https://blog.digital-forensics.it/2019/07/huawei-backup-decryptor.html._

The `kobackupdec` is a Python3 script aimed to decrypt Huawei *HiSuite* or *KoBackup* (the Android app) backups. When decrypting and uncompressing the archives, it will re-organize the output folders structure trying to _mimic_ the typical Android one. The script will work both on Windows and Linux hosts, provided the PyCryptoDome dependency. Starting from **20100107** the script was rewritten to handle v9 and v10 kobackup backups structures.

## Usage

The script *assumes* that backups are encrypted with a user-provided password. Actually it does not support the HiSuite _self_ generated password, when the user does not provide its own.

```
usage: kobackupdec.py [-h] [-v] password backup_path dest_path

Huawei KoBackup decryptor version 20190729

positional arguments:
  password       user password for the backup
  backup_path    backup folder
  dest_path      decrypted backup folder

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose level, -v to -vvv
```

- `password`, is the user provided password.
- `backup_path`, is the folder containing the Huawei backup, relative or absolute paths can be used.
- `dest_path`, is the folder to be created in the specified path, absolute or relative. It will complain if the provided folder already exists.
- `[-v]` (from `-v` to `-vvv`) verbosity level, written on *stderr*. It's suggested to use *-vvv* with a redirect to get a log of the process.

### Example

```
Z:\> py -3 kobackupdec.py -vvv 123456 "Z:\HUAWEI P30 Pro_2019-06-28 22.56.31" Z:\HiSuiteBackup
INFO:root:getting files and folder from Z:\HUAWEI P30 Pro_2019-06-28 22.56.31
INFO:root:parsing XML files...
INFO:root:parsing xml audio.xml
DEBUG:root:parsing xml file audio.xml
INFO:root:parsing xml document.xml
DEBUG:root:parsing xml file document.xml
INFO:root:parsing xml info.xml
DEBUG:root:ignoring entry HeaderInfo
DEBUG:root:ignoring entry BackupFilePhoneInfo
DEBUG:root:ignoring entry BackupFileVersionInfo
INFO:root:parsing xml picture.xml
DEBUG:root:parsing xml file picture.xml
INFO:root:parsing xml soundrecorder.xml
DEBUG:root:parsing xml file soundrecorder.xml
INFO:root:parsing xml video.xml
DEBUG:root:parsing xml file video.xml
DEBUG:root:crypto_init: using version 3.
DEBUG:root:SHA256(BKEY)[16] = b'8d969eef6ecad3c29a3a629280e686cf'
...
```

The **output** folder structure will be similar to the following one: *data/data* applications will be exploded in their proper paths, and the APKs will be *restored* too (not icons, actually). Note that the **db** folder will contain the *special* databases as created by the Huawei backups.

```
HiSuiteBackup
|-- data
|   |-- app
|   |   |-- de.sec.mobile.apk-1
|   |   | [...]
|   |   `-- org.telegram.messenger.apk-1
|   `-- data
|       |-- de.sec.mobile
|       | [...]
|       `-- org.telegram.messenger
|-- db
|   |-- HWlanucher.db
|   |-- Memo.db
|   |-- alarm.db
|   |-- calendar.db
|   |-- calllog.db
|   |-- camera.db
|   |-- clock.db
|   |-- contact.db
|   |-- harassment.db
|   |-- phoneManager.db
|   |-- setting.db
|   |-- sms.db
|   |-- soundrecorder.db
|   |-- systemUI.db
|   |-- weather.db
|   `-- wifiConfig.db
`-- storage
    |-- DCIM
    |-- Download
    |-- Huawei
    |-- MagazineUnlock
    |-- Notifications
    |-- Pictures
    |-- WhatsApp
    |-- mp3
    |-- parallel_intl
    `-- s8-wallpapers-9011.PNG
```
