#from Crypto.Cipher import AES
#import pyaes

def str_to_bitarray(s):
    # Converts string to a bit array.
    bitArr = list()
    for byte in s:
        bits = bin(byte)[2:] if isinstance(byte, int) else bin(ord(byte))[2:]
        while len(bits) < 8:
            bits = "0"+bits  # Add additional 0's as needed
        for bit in bits:
            bitArr.append(int(bit))
    return(bitArr)

def bitarray_to_str(bitArr):
    # Converts bit array to string
    result = ''
    for i in range(0,len(bitArr),8):
        byte = bitArr[i:i+8]
        s = ''.join([str(b) for b in byte])
        result = result+chr(int(s,2))
    return result

def xor(a, b):
    # xor function - This function is complete
    return [i^j for i,j in zip(a,b)]

def VernamEncrypt(binKey,block):
    # Vernam cipher
    if (len(binKey) != len(block)):
        raise Exception("Key is not same size as block")
    return xor(binKey,block)

def VernamDecrypt(binKey,block):
    # Basically a Vernam cipher.  Note it is
    # exactly the same as encryption.
    return VernamEncrypt(binKey,block)



class BlockChain():

    # Modes
    CBC = 0
    PCBC = 1
    CFB = 2
    pad=0
    
    def __init__(self,keyStr,ivStr,encryptMethod,decryptMethod,mode):
        self.encryptBlk = encryptMethod
        self.decryptBlk = decryptMethod
        self.mode = mode
        self.key = str_to_bitarray(keyStr)
        self.iv = str_to_bitarray(ivStr)
        self.ivarr = self.iv

    def addpadding(self,msg):
        if (len(msg)!=64):
            l=len(msg)
            self.pad = 64-l
            for i in range(self.pad):
                if i+l==62:
                    msg.append(1)
                else:
                    msg.append(0)
            return msg
        else:
            return msg
    def removepadding(self,msg):
        if (self.pad>0):
            n = self.pad/8
            msg = msg[:-n]
            return msg
        else:
            return msg

    def encrypt(self,msg):
        # Returns a list of cipher blocks. These blocks are
        # generated based on the mode. The message may need
        # to be padded if not a multiple of 8 bytes (64 bits).
        cipherBlks = list()
        Blksplit = [msg[k:k+8] for k in range(0, len(msg), 8)]
        self.iv = self.ivarr
        for i in range(len(Blksplit)):
            PlainText = str_to_bitarray(Blksplit[i])
            PlainText = self.addpadding(PlainText)
            if self.mode==0:
                temp = xor(PlainText, self.iv)
                temp = VernamEncrypt(self.key, temp)
                self.iv = temp
                cipherBlks.append(temp)
            if self.mode==1:
                temp = xor(PlainText, self.iv)
                temp = VernamEncrypt(self.key, temp)
                self.iv = xor(temp,PlainText)
                cipherBlks.append(temp)
            if self.mode==2:
                temp = VernamEncrypt(self.key, self.iv)
                temp = xor(PlainText, temp)
                self.iv = temp
                cipherBlks.append(temp)
        return cipherBlks

    def decrypt(self,cipherBlks):
        # Takes a list of cipher blocks and returns the
        # message. Again, decryption is based on mode.
        msg = ""
        self.iv = self.ivarr
        msgBlks = list()
        for i in range(len(cipherBlks)):
            if self.mode==0:
                temp = VernamDecrypt(self.key,cipherBlks[i])
                temp = xor(temp, self.iv)
                self.iv = cipherBlks[i]
            if self.mode==1:
                temp = VernamDecrypt(self.key,cipherBlks[i])
                temp = xor(temp, self.iv)
                self.iv = xor(temp,cipherBlks[i])
            if self.mode==2:
                temp = VernamDecrypt(self.key,self.iv)
                temp = xor(temp, cipherBlks[i])
                self.iv = cipherBlks[i]
            msg = msg + bitarray_to_str(temp)
        msg = self.removepadding(msg)
        return msg

if __name__ == '__main__':
    key = "secret_k"
    iv = "whatever"
    msg = "My name is Pujitha. There are many messages like this but this is mine."
    
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.CBC)
    cipherblks = blkChain.encrypt(msg)
    print("CBC Cipher Text:")
    for blk in cipherblks:
        print(bitarray_to_str(blk))
    print("\nCBC Decrypted Text:")
    msg1 = blkChain.decrypt(cipherblks)
    print(msg1)
    
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.PCBC)
    cipherblks = blkChain.encrypt(msg)
    print("\n\nPCBC Cipher Text:")
    for blk in cipherblks:
        print(bitarray_to_str(blk))
    print("\nPCBC Decrypted Text:")
    msg2 = blkChain.decrypt(cipherblks)
    print(msg2)
    
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.CFB)
    cipherblks = blkChain.encrypt(msg)
    print("\n\nCFB Cipher Text:")
    for blk in cipherblks:
        print(bitarray_to_str(blk))
    print("\nCFB Decrypted Text:")
    msg3 = blkChain.decrypt(cipherblks)
    print(msg3)
