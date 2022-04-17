import subprocess
import random
import tempfile
import os
import sys
import time

BLOCK_SIZE = 100000
RESULT_CLIENT_RETURN = 'client_return'
RESULT_CLIENT_STDOUT = 'client_stdout'
RESULT_SERVER_RETURN = 'server_return'
RESULT_SERVER_STDOUT = 'server_stdout'

def run_transfer(file, dest):
    server = subprocess.Popen(
        "quiccat -listen:* -port:8888 -destination:" + dest, stdout=subprocess.PIPE)
    time.sleep(1)
    client = subprocess.Popen(
        "quiccat -target:127.0.0.1 -port:8888 -file:" + file, stdout=subprocess.PIPE)
    server.wait()
    client.wait()
    result = dict()
    result[RESULT_CLIENT_RETURN] = client.returncode
    result[RESULT_CLIENT_STDOUT] = client.stdout.read()
    result[RESULT_SERVER_RETURN] = server.returncode
    result[RESULT_SERVER_STDOUT] = server.stdout.read()
    return result

def create_file(filename, size):
    r = random.Random()
    bytes_remaining = size
    with open(filename, "wb") as file:
        while bytes_remaining > 0:
            if bytes_remaining < BLOCK_SIZE:
                data = r.randbytes(bytes_remaining)
                bytes_remaining -= bytes_remaining
            else:
                data = r.randbytes(BLOCK_SIZE)
                bytes_remaining -= BLOCK_SIZE
            file.write(data)

def compare_files(file1, file2):
    with open(file1, 'rb') as f1:
        with open(file2, 'rb') as f2:
            f1_bytes = f1.read(BLOCK_SIZE)
            f2_bytes = f2.read(BLOCK_SIZE)
            while (len(f1_bytes) != 0 or len(f2_bytes) != 0):
                if len(f1_bytes) != len(f2_bytes):
                    print('file sizes differ!')
                    return False
                idx = 0
                while (idx < len(f1_bytes)):
                    if f1_bytes[idx] != f2_bytes[idx]:
                        print('file contents differ')
                        return False
                    idx += 1
                f1_bytes = f1.read(BLOCK_SIZE)
                f2_bytes = f2.read(BLOCK_SIZE)
            return True

def transfer_test(size):
    print('Testing transfer of a ' + str(size) + ' byte file...', end='', flush=True)
    with tempfile.TemporaryDirectory(prefix='src') as srcTemp:
        with tempfile.TemporaryDirectory(prefix='dest') as destTemp:
            srcFileName = "Test_" + str(size) + ".tmp"
            srcFilePath = srcTemp + os.path.sep + srcFileName
            create_file(srcFilePath, size)
            results = run_transfer(srcFilePath, destTemp)
            if results[RESULT_CLIENT_RETURN] != 0:
                print(results[RESULT_CLIENT_STDOUT])
                sys.exit("Client return was non-zero! " + str(results[RESULT_CLIENT_RETURN]))
            if results[RESULT_SERVER_RETURN] != 0:
                print(results[RESULT_SERVER_STDOUT])
                sys.exit("Server return was non-zero! " + str(results[RESULT_SERVER_RETURN]))
            if not compare_files(srcFilePath, destTemp + os.path.sep + srcFileName):
                print(results[RESULT_CLIENT_STDOUT])
                print(results[RESULT_SERVER_STDOUT])
                sys.exit("Transferred file was not identical!")
            print(' Success!')

if __name__ == '__main__':
    transfer_test(1000)
    transfer_test(100000)
    transfer_test(200000)
    transfer_test(1000000)
    transfer_test(100000000)
