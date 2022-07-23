from __future__ import division
from __future__ import print_function
import logging
import os
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import LocalOperations, NTDSHashes


class DumpSecrets:
    def __init__(self,system_hive_path,ntds_path,out_path):
        self.__useVSSMethod = False
        self.__remoteName = 'LOCAL'
        self.__remoteHost = ''
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = ''
        self.__smbConnection = None
        self.__NTDSHashes = None
        self.__systemHive = system_hive_path
        self.__ntdsFile = ntds_path
        self.__history = ''
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = out_path
        self.__doKerberos = False
        self.__justDCNTLM = False
        self.__justUser = False
        self.__pwdLastSet = False
        self.__printUserStatus= False
        self.__resumeFileName = False
        self.__kdcHost = False

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            
            self.__isRemote = False
            self.__useVSSMethod = True
            if self.__systemHive:
                localOperations = LocalOperations(self.__systemHive)
                bootKey = localOperations.getBootKey()
                if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                    self.__noLMHash = localOperations.checkNoLMHashPolicy()

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
              
            NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                               noLMHash=self.__noLMHash, remoteOps='',
                                               useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                               pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                               outputFileName=self.__outputFileName, justUser=self.__justUser,
                                               printUserStatus= self.__printUserStatus)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                logging.error(e)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    logging.info("You just got that error because there might be some duplicates of the same name. "
                                     "Try specifying the domain name for the user as well. It is important to specify it "
                                     "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                        logging.info('Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter')
                self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()