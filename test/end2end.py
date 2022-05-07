import subprocess
import random
import tempfile
import os
import sys
import time

BLOCK_SIZE = 100000
QUICCAT_BLOCK_SIZE = 131072
RESULT_CLIENT_RETURN = 'client_return'
RESULT_CLIENT_STDOUT = 'client_stdout'
RESULT_CLIENT_STDERR = 'client_strerr'
RESULT_SERVER_RETURN = 'server_return'
RESULT_SERVER_STDOUT = 'server_stdout'
RESULT_SERVER_STDERR = 'server_stderr'

def run_transfer(File: str, Dest: str) -> dict:
    server = subprocess.Popen(
        ["./quiccat", "-listen:*", "-port:8888", "-destination:" + Dest], stderr=subprocess.PIPE)
    time.sleep(1)
    client = subprocess.Popen(
        ["./quiccat", "-target:127.0.0.1", "-port:8888", "-file:" + File], stderr=subprocess.PIPE)
    server.wait()
    client.wait()
    result = dict()
    result[RESULT_CLIENT_RETURN] = client.returncode
    result[RESULT_CLIENT_STDERR] = client.stderr.read()
    result[RESULT_SERVER_RETURN] = server.returncode
    result[RESULT_SERVER_STDERR] = server.stderr.read()
    return result

def run_stdout_transfer(File: str, Dest: str) -> dict:
    server = subprocess.Popen(
        ' '.join(["{}quiccat".format('.' + os.path.sep), "-listen:*", "-port:8888", ">", Dest]),
        stderr=subprocess.PIPE,
        shell=True)
    time.sleep(1)
    client = subprocess.Popen(
        ' '.join(["{}quiccat".format('.' + os.path.sep), "-target:127.0.0.1", "-port:8888", "<", File]),
        stderr=subprocess.PIPE,
        shell=True)
    server.wait()
    client.wait()
    result = dict()
    result[RESULT_CLIENT_RETURN] = client.returncode
    result[RESULT_CLIENT_STDERR] = client.stderr.read()
    result[RESULT_SERVER_RETURN] = server.returncode
    result[RESULT_SERVER_STDERR] = server.stderr.read()
    return result

def run_stdout_handles():
    print("Testing transfer using stdin/stdout file handles...", end='', flush=True)
    server = subprocess.Popen(
        ["{}quiccat".format('.' + os.path.sep), "-listen:*", "-port:8888"],
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    time.sleep(1)
    client = subprocess.Popen(
        ["{}quiccat".format('.' + os.path.sep), "-target:127.0.0.1", "-port:8888"],
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    time.sleep(1)
    if (client.stderr.read(10) != server.stderr.read(10) != b'Connected!'):
        exit("client and server didn't get connected")
    r = random.Random()
    expected = r.randbytes(QUICCAT_BLOCK_SIZE)
    client.stdin.write(expected)
    result = server.stdout.read(len(expected))
    if result != expected:
        print("{} vs {}".format(expected.hex(), result.hex()))
        exit("Client-sent data doesn't match!")
    server.stdin.write(expected)
    result = client.stdout.read(len(expected))
    if result != expected:
        print("{} vs {}".format(expected.hex(), result.hex()))
        exit("Server-sent data doesn't match!")
    client.stdin.close()
    server.wait()
    client.wait()
    print(" Success!")

def run_stdinout_close():
    print("Testing closing connection when client closes stdin...", end='', flush=True)
    with subprocess.Popen(
        ["{}quiccat".format('.' + os.path.sep), "-listen:*", "-port:8888"],
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE) as server:
        time.sleep(1)
        with subprocess.Popen(
            ["{}quiccat".format('.' + os.path.sep), "-target:127.0.0.1", "-port:8888"],
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE) as client:
            time.sleep(1)
            if (client.stderr.read(10) != server.stderr.read(10) != b'Connected!'):
                exit("client and server didn't get connected")
            client.stdin.close()
            server.wait(3)
    print(" Success!")
    print("Testing closing connection when server closes stdin...", end='', flush=True)
    with subprocess.Popen(
        ["{}quiccat".format('.' + os.path.sep), "-listen:*", "-port:8888"],
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE) as server:
        time.sleep(1)
        with subprocess.Popen(
            ["{}quiccat".format('.' + os.path.sep), "-target:127.0.0.1", "-port:8888"],
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE) as client:
            time.sleep(1)
            if (client.stderr.read(10) != server.stderr.read(10) != b'Connected!'):
                exit("client and server didn't get connected")
            server.stdin.close()
            client.wait(3)
    print(" Success!")

def create_file(Filename: str, Size: int):
    r = random.Random()
    bytes_remaining = Size
    with open(Filename, "wb") as file:
        while bytes_remaining > 0:
            if bytes_remaining < BLOCK_SIZE:
                data = r.randbytes(bytes_remaining)
                bytes_remaining -= bytes_remaining
            else:
                data = r.randbytes(BLOCK_SIZE)
                bytes_remaining -= BLOCK_SIZE
            file.write(data)

def compare_files(File1: str, File2: str) -> bool:
    with open(File1, 'rb') as f1:
        with open(File2, 'rb') as f2:
            f1Bytes = f1.read(BLOCK_SIZE)
            f2Bytes = f2.read(BLOCK_SIZE)
            while (len(f1Bytes) != 0 or len(f2Bytes) != 0):
                if len(f1Bytes) != len(f2Bytes):
                    print('file sizes differ!')
                    return False
                if f1Bytes != f2Bytes:
                    print('file contents differ')
                    return False
                f1Bytes = f1.read(BLOCK_SIZE)
                f2Bytes = f2.read(BLOCK_SIZE)
            return True

def transfer_test(Size: int):
    print('Testing transfer of a ' + str(Size) + ' byte file...', end='', flush=True)
    with tempfile.TemporaryDirectory(prefix='src') as srcTemp:
        with tempfile.TemporaryDirectory(prefix='dest') as destTemp:
            srcFileName = "Test_" + str(Size) + ".tmp"
            srcFilePath = srcTemp + os.path.sep + srcFileName
            create_file(srcFilePath, Size)
            results = run_transfer(srcFilePath, destTemp)
            if results[RESULT_CLIENT_RETURN] != 0:
                print(results[RESULT_CLIENT_STDERR])
                sys.exit("Client return was non-zero! " + str(results[RESULT_CLIENT_RETURN]))
            if results[RESULT_SERVER_RETURN] != 0:
                print(results[RESULT_SERVER_STDERR])
                sys.exit("Server return was non-zero! " + str(results[RESULT_SERVER_RETURN]))
            if not compare_files(srcFilePath, destTemp + os.path.sep + srcFileName):
                print(results[RESULT_CLIENT_STDERR])
                print(results[RESULT_SERVER_STDERR])
                sys.exit("Transferred file was not identical!")
            print(' Success!')

def stdinout_transfer_test(Size: int):
    print('Testing transfer of a ' + str(Size) + ' byte file via stdout...', end='', flush=True)
    with tempfile.TemporaryDirectory() as tempDir:
        srcFileName = "Src_" + str(Size) + ".tmp"
        srcFilePath = tempDir + os.path.sep + srcFileName
        destFileName = "Dest_" + str(Size) + ".tmp"
        destFilePath = tempDir + os.path.sep + destFileName
        create_file(srcFilePath, Size)
        results = run_stdout_transfer(srcFilePath, destFilePath)
        if results[RESULT_CLIENT_RETURN] != 0:
            print(results[RESULT_CLIENT_STDERR])
            sys.exit("Client return was non-zero! " + str(results[RESULT_CLIENT_RETURN]))
        if results[RESULT_SERVER_RETURN] != 0:
            print(results[RESULT_SERVER_STDERR])
            sys.exit("Server return was non-zero! " + str(results[RESULT_SERVER_RETURN]))
        if not compare_files(srcFilePath, destFilePath):
            print(results[RESULT_CLIENT_STDERR])
            print(results[RESULT_SERVER_STDERR])
            sys.exit("Transferred file was not identical!")
        print(' Success!')

if __name__ == '__main__':
    run_stdinout_close()
    run_stdout_handles()
    for size in [1000, 100000, 200000, 1000000, 100000000]:
        # transfer_test(size)
        stdinout_transfer_test(size)
