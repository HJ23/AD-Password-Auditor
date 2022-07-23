import os
import hashlib,binascii
import os
from concurrent.futures import ThreadPoolExecutor
from .secretsdump import DumpSecrets

class DomainUsername:
    DOMAIN=""
    USERNAME=""

class PasswordGenerator:
    def __init__(self,obj) -> None:
        self.username=obj.USERNAME
        self.domain=obj.DOMAIN
        self.generated=set()
        self.rockyou_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","filtered_rockyou.txt")
    def __number_with_leading_zeros_generator(self):
        for x in range(0,10000):
            string_num=str(x)
            for y in range(4-len(string_num)):
                string_num="0"+string_num
                self.generated.add(string_num)
            self.generated.add(str(x))
    def __numpad_generator(self):
        self.generated.add("741852963")
        self.generated.add("147258369")
        self.generated.add("789456123")
    def __number_sequence_generator(self):
        for x in range(1,11):
            tmp=""
            for y in range(0,x):
                tmp+=str(y)
            self.generated.add(tmp)
            self.generated.add(tmp[::-1])
        for x in range(2,11):
            tmp=""
            for y in range(1,x):
                tmp+=str(y)
            self.generated.add(tmp)
            self.generated.add(tmp[::-1])
    def __combiner(self,name_combination):
        tmp=set()
        for name in name_combination:
            for presufix in self.generated:
                tmp.add(name+presufix+"!")
                tmp.add("!"+name+presufix)
                tmp.add("!"+presufix+name)
                tmp.add(name+"!"+presufix)
                tmp.add(presufix+name+"!")
                tmp.add(presufix+"!"+name)
                tmp.add(name+presufix)
                tmp.add(presufix+name)
        self.generated=self.generated|tmp
        self.generated=list(filter(lambda x:len(x)>6,self.generated))
        return self.generated
    def start(self):
        self.__number_with_leading_zeros_generator()
        self.__numpad_generator()
        self.__number_sequence_generator()
        name_combination=set([self.username,self.username+self.domain,self.domain+self.username,
                                   self.username[0].upper()+self.username[1:],self.username[0].lower()+self.username[1:] ])
        if(self.domain!=""):
            name_combination.add(self.domain)
            name_combination.add(self.domain+"\\"+self.username)
        return self.__combiner(name_combination)

class Hasher(object):
    def __init__(self,num_threads) -> None:
        self.num_threads=num_threads
    
    def hasher(self,password):
        hash = hashlib.new('md4', password.encode('utf-16le')).digest()
        return password,binascii.hexlify(hash).decode('utf-8')

    def start(self,passwords):
        futures=[]
        outputs={}
        with ThreadPoolExecutor(self.num_threads) as executor:
            for password in passwords:
                futures.append(executor.submit(self.hasher,password))
        for future in futures:
            password,hash=future.result()
            outputs[hash]=password
        return outputs

class DumpADsecrets:
    def __init__(self) -> None:
        pass
    def clean(self):
        if(os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds"))):
            os.remove((os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds")))
        if(os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds.cleartext"))):
            os.remove(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds.cleartext"))
        if(os.path.exists(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds.kerberos"))):
            os.remove(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds.kerberos"))
        
    def start(self):
        self.clean()
        file_outputs=[]
        final_outputs={}
        ntds_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","ntds.dit")
        system_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","system")
        out_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out")
        dumper = DumpSecrets(system_path,ntds_path,out_path)
        try:
            dumper.dump()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(e)
            self.clean()
            return None
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","secretsdump_out.ntds"),"r",encoding="utf-8",errors='replace') as file:
            file_outputs=file.readlines()
        file_outputs=list(map(lambda x:x.replace("\n","").strip(),file_outputs))
        for line in file_outputs:
            if(line!=""):
                obj=DomainUsername()
                password_hash=line.split(":")[3]
                obj.USERNAME=line.split(":")[0]
                if("\\" in obj.USERNAME and not (obj.USERNAME.startswith(".") or \
                               obj.USERNAME.startswith("local") )):
                               obj.DOMAIN=obj.USERNAME.split("\\")[0]
                               obj.USERNAME=obj.USERNAME.split("\\")[1]
                else:
                    obj.USERNAME=obj.USERNAME.split("\\")[0]
                final_outputs[password_hash]=obj
        self.clean()
        return final_outputs