import debugger

unpackIt = debugger.debugger()

packed_malware = input("Enter the path of the file to unpack: ")
print("The malware entered is: %s" % packed_malware)

unpackIt.load("C:\\Users\\rjimersonjr\\Documents\\GitHub\\helloWorldBinary\\helloWorldBinary\\Release\\helloWorldBinary.exe")