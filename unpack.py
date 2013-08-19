import debugger

unpackIt = debugger.debugger()

#packed_malware = input("Enter the path of the file to unpack: ")

#unpackIt.load("C:\\Users\\rjimersonjr\\Documents\\GitHub\\helloWorldBinary\\helloWorldBinary\\Release\\helloWorldBinary.exe")
path_to_dll = "C:\\Users\\rjimersonjr\\Documents\\GitHub\\malDLL\\malDLL\\Release\\dllToHook.dll"
packed_malware = "C:\\Users\\rjimersonjr\\Documents\\GitHub\\helloWorldBinary\\helloWorldBinary\\Release\\helloWorldBinary.exe"
unpackIt.load(packed_malware, path_to_dll)