# Setup file for compiling the python script with cx_Freeze (https://github.com/anthony-tuininga/cx_Freeze)

from cx_Freeze import setup, Executable

executables = [
    Executable('kobackupdec.py')
]

setup(name='KoBackupDec',
# Change build number to the current one
    version='20200607',
    description='HiSuite / KoBackup Decryptor',
    executables=executables
)

# Compile the python script to an executable with: python setup.py build
# Build an Windows installation Package with: python setup.py bdist_msi
