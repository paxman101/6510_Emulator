byte_arr = bytearray()
with open('AllSuiteA.rom') as file:
    for line in file:
        if line[0] != '/':
            byte_arr += bytearray.fromhex(line);

with open('AllSuiteA.bin', 'wb') as file:
    file.write(byte_arr)
