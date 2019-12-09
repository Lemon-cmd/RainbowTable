from rainbowtable import *

"""Get the rainbow table path and input the target hash"""

rain_path = input(str('Enter the path to the rainbow table: '))
target_hash = input(str('Enter the target hash: '))

def crack(path, target):
    #create a rainbow table object
    rainbow = RainbowTable()

    #read the table
    rainbow.readFromFile(path)

    #return the cracked password
    return rainbow.crackHash(target)

#print the cracked password
print(crack(rain_path, target_hash))
