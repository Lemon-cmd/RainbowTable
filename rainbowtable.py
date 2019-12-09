lettersLower = 'abcdefghijklmnopqrstuvwxyz'
lettersUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
numbers = "0123456789"
allChars = lettersLower + lettersUpper + numbers

from hashlib import md5
import sys
from random import randrange, getstate, setstate
import pickle

class RainbowTable:
    """Rainbow table: Structure to crack hashed passwords."""
    # Dictionary for finding hash functions by their name.
    hashFunctions = {'': None, md5.__name__ : md5, 'md5' : md5}

    
    def __init__(self, continueWrite= False, randomstate= None, columns=0, chars="", pwdLength=0, func='',
                 rows=0):
        """Initializes the rainbow table.
        columns: Length of a chain, i.e. number of times the password at the start of the chain is hashed and reduced.
        chars: List of characters covered.
        pwdLength: Length of the passwords.
        func: Name of the hashing function.
        rows: Number of chains.
        """
        
        from RB import RBTree, rbnode
        self.table = RBTree()
        self.state = randomstate
        self.Cont_Write = continueWrite

        #check if continue to write into 1 file is true
        if self.Cont_Write is True and self.state is not None:
            setstate(self.state)
        
        if columns > 0:
            self.columns = columns
            self.chars = chars
            self.pwdLength = pwdLength
            self.func = RainbowTable.hashFunctions[func]
            for i in range(rows):
                if i % 100000 == 0:
                    print("Progress: ", i)
                pwd = self.randomPassword()
                hashV = self.createChain(pwd)
                self.table.insert(hashV, pwd)
            #save the random generator seed when done
            self.save_random_state(getstate())
                
    def createChain(self, pwd):
        """Creates a chain. pwd: Password to start the chain with."""
        for col in range(self.columns):
            hashV = self.hashWord(pwd)
            pwd = self.reduce(hashV, col)

        #return hash chain
        return hashV
    
    def save_random_state(self, state):
        #save the state onto the pickle file
        with open("RandomState.pickle", 'wb') as f:
            pickle.dump(state, f)

    def randomPassword(self):
        """Generates a random password & Returns the generated password."""
        pwd = ""
        charsLength = len(self.chars)
        for i in range(self.pwdLength):
            pwd += self.chars[randrange(charsLength)]
        return pwd

    def reduce(self, hashV, column):
        """Reduces a hash.
        hashV: Hash to reduce.
        column: Column to hash at.
        Returns a valid password.
        """
        results = []
        # Cast hash from str to int then decompose into bytes
        byteArray = self.getBytes(hashV)
        for i in range(self.pwdLength):
            index = byteArray[(i + column) % len(byteArray)]
            newChar = self.chars[index % len(self.chars)]
            results.append(newChar)
        return "".join(results)
    
    def __repr__(self):
        """Prints the content of the table."""
        return repr(self.table._root)

    def getBytes(self, hashV):
        """Transforms a hash into a list of bytes.
        hashV: Hash to transform into bytes.
        Returns a list of bytes.
        """    
        results = []
        remaining = int(hashV, 16)
        while remaining > 0:
            results.append(remaining % 256)
            remaining //= 256
        return results
    
    def writeToFile(self, output):
        """Writes rainbow table into a file, so that it can be recovered at a different time later."""
        f = open(output, 'w')
        data = [self.columns, self.chars, self.pwdLength, self.func.__name__]
        data = [str(x) for x in data]
        f.write(" ".join(data))
        f.write("\n")
        f.write(repr(self))
        f.close()

    def continueWriting(self, input):
        #open the file and append to it
        f = open(input, 'a')
        data = [self.columns, self.chars, self.pwdLength, self.func.__name__]
        data = [str(x) for x in data]
        f.write(" ".join(data))
        f.write("\n")
        f.write(repr(self))
        f.close()

    def readFromFile(self, input):
        """Read a rainbow table from a file."""
        f = open(input, "r")
        line = f.readline()
        line = line.strip().split(sep=" ", maxsplit=3)
        self.columns, self.chars, self.pwdLength, self.func = line
        self.columns = int(self.columns)
        self.pwdLength = int(self.pwdLength)
        self.func = RainbowTable.hashFunctions[self.func]
        line = f.readline()
        while line != '':
            pwd, hashV = line.strip().split(sep=" ", maxsplit=1)
            self.table.insert(hashV, pwd)
            line = f.readline()
        f.close()


    def _find(self, hashV):
        """Find the passwords in the table corresponding to the given hash.
        hashV: Hash to find.
        Returns a list of corresponding starting passwords.
        """
        return self.table.search(hashV)


    def hashWord(self, word):
        """Hash a word.
        word: Word to hash.
        Returns the hash of the word.
        """
        word = word.encode('utf-8')
        return self.func(word).hexdigest()

    def crackHash(self, startHash):
        """Tries to crack a hash. startHash: Hash to crack.
        Returns the resulting password, if one is found, '' otherwise."""
        
        for col in range(self.columns, -1, -1):
            hashV = self._getFinalHash(startHash, col)
            pwdList = self._find(hashV)
            for pwd in pwdList:
                resPwd = self._findHashInChain(pwd, startHash)
                if resPwd != None:
                    return resPwd
           
        return 'None'


    def _getFinalHash(self, startHash, startCol):
        """Returns the hash at the end of a chain, starting from a hash and at a given column.
        startHash: Hash to start with.
        startCol: Column to start from.
        Returns the hash at the end of a chain."""
        hashV = startHash
        for col in range(startCol, self.columns-1):
            pwd = self.reduce(hashV, col)
            hashV = self.hashWord(pwd)
        return hashV


    def _findHashInChain(self, startPwd, startHash):
        """Tries to find a hash in a chain.
        startPwd: Password at the beginning of a chain.
        startHash: Hash to find.
        Returns the corresponding password if one is found, None otherwise.
        """
        hashV = self.hashWord(startPwd)
        if hashV == startHash:
            return startPwd
        col = 0
        # hash and reduce until the password has been found or the end of the chain has been reached.
        while col < self.columns:
            pwd = self.reduce(hashV, col)
            hashV = self.hashWord(pwd)
            if hashV == startHash:
                # If the password has been found, return it
                return pwd
            col += 1
	# The password hasn't been found, return None.
        return None


    def allPasswords(self):
        """Returns the list of all password this table could and should cover."""
        res = []
        length = len(self.chars)
        for i in range(length**self.pwdLength):
            pwd = ""
            for j in range(self.pwdLength):
                pwd += self.chars[i % length]
                i //= length
            res.append(pwd)
        return res



def load_random_state():
    state = 0
    with open("RandomState.pickle", 'rb') as f:
        state = (pickle.load(f))

    return state

