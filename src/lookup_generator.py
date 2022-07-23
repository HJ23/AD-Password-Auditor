from asyncio import as_completed
import hashlib,binascii
import os
from concurrent.futures import ThreadPoolExecutor

def read_and_prepare(password_file):
    path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..",password_file)
    passwords=[]
    with open(path,"r",encoding="utf-8",errors="replace") as file:
        passwords=file.readlines()
    passwords=set(map(lambda x:x.replace("\n","").strip(),passwords))
    return passwords

def hasher(password):
    hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    return password,binascii.hexlify(hash).decode('utf-8')

def start(password_file,num_thread):
    futures=[]
    output_string=""
    passwords=read_and_prepare(password_file)
    with ThreadPoolExecutor(num_thread) as executor:
        for password in passwords:
            futures.append(executor.submit(hasher,password))
    for i,future in enumerate(futures):
        print(i)
        password,hash=future.result()
        output_string+=password+":"+hash+"\n"

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","lookup_table.txt"),"w",encoding="utf-8",errors="replace") as file:
        file.writelines(output_string)

start("filename",100)