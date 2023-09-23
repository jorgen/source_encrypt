import argparse
import glob
import sys
import sysconfig
from setuptools import Extension, setup
from Crypto.Random import get_random_bytes
import binascii
import shutil
import sys
import tempfile
import packaging.tags
import os
import os.path

from contextlib import contextmanager

from .encryption import encrypt_aes

@contextmanager
def tempdir():
    path = tempfile.mkdtemp()
    try:
        yield path
    finally:
        try:
            shutil.rmtree(path)
        except IOError:
            sys.stderr.write('Failed to clean up temp dir {}'.format(path))

def create_key() -> None:
    print(binascii.hexlify(get_random_bytes(32)).decode('utf-8'))

def get_printable_bytes(b: bytes) -> bytes:
    return b'0x' + binascii.hexlify(b).upper()

def get_printable_string(b: bytes) -> bytes:
    return f"0x{binascii.hexlify(b).decode()}"

def gen_runtime(key: bytes, output_folder_root: str) -> None:
    base_folder = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    packaging_tag = next(packaging.tags.sys_tags())

    hexkey_variable = get_random_bytes(1)
    fill_size = len(key)
    counter = 0
    key_data = b''
    for k in key:
        key_data += f"*(data + {counter}) = {get_printable_string(bytes([k]))} ^ XORKEY;\n".encode()
        counter+=1
    key_data += f"*len = {hex(counter)};\n".encode()
        
    with tempdir() as temp_dir:
        # Read in key_template.h and replace the CREATE_KEY_HERE with the key variable and write to temp_dir/key.h
        with open(f"{base_folder}/template_py/key_template.h", 'rb') as f:
            key_template = f.read()
            key_template = key_template.replace(b"/*FILL RANDOM BYTE HERE*/", get_printable_bytes(hexkey_variable)) 
            key_template = key_template.replace(b"/*FILL SIZE HERE*/", get_printable_bytes(bytes([fill_size])))
            key_template = key_template.replace(b"/*FILL DATA HERE*/", key_data)

        with open(f"{temp_dir}/key.h", 'wb') as f:
            f.write(key_template)

        shutil.copyfile(f"{temp_dir}/key.h", f"{base_folder}/tmp_key.h")

        sys.argv = sys.argv[:1]
        sys.argv.append("build")
        sys.argv.append(f"--build-base={temp_dir}")
        setup(
            ext_modules=[
                Extension(
                    name="source_encrypt_native",  # as it would be imported
                                       # may include packages/namespaces separated by `.`
                    sources=["c_src/native.c",
                             "c_src/aes.c",
                             "c_src/sha256.c"], # all sources are compiled into a single binary file
                    include_dirs=[temp_dir],  # include path for headers
                    define_macros=[("KEY", key)],
                ),
        ]
        )
        output_folder = f"{output_folder_root}/{packaging_tag.platform}/{packaging_tag.interpreter}-{packaging_tag.abi}/source_encrypt_runtime"
        os.makedirs(output_folder, exist_ok=True)
        shared_object = glob.glob(f"{temp_dir}/**/*.pyd", recursive=True)
        module_extension = os.path.splitext(sysconfig.get_config_var('EXT_SUFFIX'))[-1]

        shutil.copyfile(shared_object[0], f"{output_folder}/source_encrypt_native{module_extension}")
        shutil.copyfile(f"{base_folder}/template_py/__init__.py.template", f"{output_folder}/__init__.py")
        
def obfuscate_python_file(source, destination, key):
    with open(source, 'rb') as f:
        source_code = f.read()
    [encrypted, salt_and_iv] = encrypt_aes(source_code, key)
    content = f"""# Generated Python source file
import os
import source_encrypt_runtime
source_encrypt_runtime.decrypt({encrypted}, {salt_and_iv}, __file__, int(os.path.getmtime(__file__)))
    """
    with open(destination, 'wb') as f:
        f.write(content.encode())

class RedirectStdoutToFile:
    def __init__(self, file):
        self.file = file
        self.stdout = sys.stdout

    def __enter__(self):
        sys.stdout = self.file

    def __exit__(self, exc_type, exc_value, traceback):
        sys.stdout = self.stdout

def create_args(parser):
    if parser.destination_file:
        with open(parser.destination_file, 'wb') as file, RedirectStdoutToFile(file):
            create_key()
    else:
        create_key()

def runtime_args(parser):
    with open(parser.key_file, "rb") as file:
        key = file.read().strip()
    gen_runtime(key, "outfolder")
    print(f"runtime- {parser}")

def obfuscate_args(parser):
    with open(parser.key_file, "rb") as file:
        key = file.read().strip()
    obfuscate_python_file(parser.source_file, parser.destination_file, key)

def main():
    parser = argparse.ArgumentParser(description='Encrypt Python code')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    subparsers = parser.add_subparsers(dest="command", required=True, help='sub-command help')
    create_parser = subparsers.add_parser('key', aliases=['k'], help='Create a new key')
    create_parser.set_defaults(func=create_args)
    create_parser.add_argument('destination_file', nargs="?", help='The destination file for the key') 
    runtime_parser = subparsers.add_parser('runtime', aliases=['r'], help='Generate the runtime')
    runtime_parser.set_defaults(func=runtime_args)
    runtime_parser.add_argument('-k', '--key_file', required=True, help='The key to use for the runtime')
    runtime_parser.add_argument('destination_folder', help='The destination folder for the runtime')
    obfuscate_parser = subparsers.add_parser('obfuscate', aliases=['o'], help='Obfuscate a python file')
    obfuscate_parser.set_defaults(func=obfuscate_args)
    obfuscate_parser.add_argument('-k', '--key_file', required=True, help='The key to use for the obfuscation')
    obfuscate_parser.add_argument('-s', '--source_file', help='The source file to obfuscate')
    obfuscate_parser.add_argument('-d', '--destination_file', help='The destination file for the obfuscated file')
    args = parser.parse_args()
    
     # If no subcommand and no --version is provided, show error
    if 'func' not in args:
        parser.error("a subcommand is required")

    # Call the associated function if a subcommand was provided
    if hasattr(args, 'func'):
        args.func(args)

if __name__ == "__main__":
    main()