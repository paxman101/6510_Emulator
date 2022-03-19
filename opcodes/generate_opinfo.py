import re
import urllib.request

info_url = "https://raw.githubusercontent.com/mist64/c64ref/master/Source/6502/cpu_6502.txt"
response = urllib.request.urlopen(info_url)
data = response.read().decode("utf-8")

start = data.find("[timing]")
end = data.find("[vectors]")
data = data[start:end]

results = re.findall(r"^(\w\w) {2}(\d)(.*p)?", data, re.MULTILINE)

for matches in results:
    print(f"OPCODE_INFO_VEC[0x{matches[0]}].num_cycles = {matches[1]};")
    if matches[2] != '':
        print(f"OPCODE_INFO_VEC[0x{matches[0]}].extra_cycle_if_cross = true;")
