import sys
import json
from androguard.misc import AnalyzeAPK
import re

arguments = sys.argv

if len(arguments) != 3:
    print("Incorrect input format")
    print("Correct format: python task1.py input_file_path output_json_path")
    sys.exit(1)

input_file_path = arguments[1]
output_json_path = arguments[2]

# analyze apk to get manifest, dalvik and analysis objects
apk_obj, dalvik_obj, analysis_obj = AnalyzeAPK(input_file_path)

# input files for system commands and permission mapping
commands_file = "System_Commands.txt"
permission_file = "SmallCasePScoutPermApiDict.json"

# initialize dicts and sets for features
API_call_freq = {}
API_package_freq = {}
Opcode_freq = {}
Presence_of_reflection = {
    "ClassforName" : False,
    "DexClassLoader" : False,
    "SystemloadLibrary" : False
}
Network_addresses = []
Restricted_APIs = []
Used_permissions = []
System_commands_set = set()

# load system commands
with open(commands_file, 'r', encoding='utf-8') as file:
    for line in file:
        if line.strip():
            System_commands_set.add(line.strip())

# load permission mapping
with open(permission_file, 'r', encoding='utf-8') as file:
    map_permissions = json.load(file)

# prepare api to permission mapping
api_to_permission_map = {}
for permission, api_list in map_permissions.items():
    for api_details in api_list:
        class_name = api_details[0].lower()
        function_name = api_details[1].lower()
        api_key = f"{class_name}->{function_name}"
        api_to_permission_map[api_key] = permission

# sets to track used and restricted permissions
permissions_declared = set(apk_obj.get_permissions())
permissions_used = set()
restricted_apis_set = set()
network_addresses_set = set()

system_commands_freq = {}

# regex for ip and domain
ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
domain_pattern = re.compile(r'https?://([a-zA-Z0-9.-]+)')

# check strings for network addresses and system commands
for s in dalvik_obj[0].get_strings():
    if ip_pattern.search(s) or domain_pattern.search(s) and not s.endswith(".java"):
        network_addresses_set.add(s)
    for word in s.split():
        if word in System_commands_set:
            system_commands_freq[word] = system_commands_freq.get(word, 0) + 1

# iterate over classes and methods
for Class in dalvik_obj[0].get_classes():
    for function in Class.get_methods():
        code = function.get_code()
        if code:
            # opcode frequency
            instructions = code.get_bc().get_instructions()
            for instruction in instructions:
                opcode_name = instruction.get_name()
                Opcode_freq[opcode_name] = Opcode_freq.get(opcode_name, 0) + 1

            # analyze method calls
            analysis_method = analysis_obj.get_method(function)
            if analysis_method:
                for _, call, _ in analysis_method.get_xref_to():
                    class_name = call.class_name
                    function_name = call.name

                    # construct api call string
                    API_call = f"{class_name[1:-1].replace('/','.')}.{function_name}"
                    API_call_freq[API_call] = API_call_freq.get(API_call, 0) + 1

                    # derive package name
                    parts = API_call.split(".")
                    if len(parts) > 2:
                        package_name = ".".join(parts[:-2])
                    else:
                        package_name = parts[0]

                    API_package_freq[package_name] = API_package_freq.get(package_name, 0) + 1

                    # check reflection/dynamic/native usage
                    api_key = f"{class_name}->{function_name}"
                    if "Ljava/lang/Class;->forName" in api_key:
                        Presence_of_reflection["ClassforName"] = True
                    if "Ldalvik/system/DexClassLoader;-><init>" in api_key:
                        Presence_of_reflection["DexClassLoader"] = True
                    if "Ljava/lang/System;->loadLibrary" in api_key:
                        Presence_of_reflection["SystemloadLibrary"] = True

                    # map api to permission
                    class_name_for_mapping = class_name[1:-1].replace('/', '.').lower()
                    function_name_for_mapping = function_name.lower()
                    if function_name_for_mapping == "<init>":
                        function_name_for_mapping = class_name_for_mapping.split('.')[-1]
                    
                    api_key_for_mapping = f"{class_name_for_mapping}->{function_name_for_mapping}"
                    
                    if api_key_for_mapping in api_to_permission_map:
                        perm_needed = api_to_permission_map[api_key_for_mapping]
                        permissions_used.add(perm_needed)
                        if perm_needed not in permissions_declared:
                            restricted_apis_set.add(API_call)

# prepare final outputs
System_commands = dict(sorted(system_commands_freq.items(), key=lambda item: item[1], reverse=True))
Restricted_APIs = sorted(list(restricted_apis_set))
Used_permissions = sorted(list(permissions_used))
Network_addresses = sorted(list(network_addresses_set))

# final dictionary of features
final_dict = {
    "NetworkAddresses": Network_addresses,
    "RestrictedAPIs": Restricted_APIs,
    "UsedPermissions": Used_permissions,
    "APICallFrequency": dict(sorted(API_call_freq.items(), key=lambda item: item[1], reverse=True)),
    "APIPackageFrequency": dict(sorted(API_package_freq.items(), key=lambda item: item[1], reverse=True)),
    "OpcodeFrequency": dict(sorted(Opcode_freq.items(), key=lambda item: item[1], reverse=True)),
    "ReflectionDynamicNative": Presence_of_reflection,
    "SystemCommands": System_commands
}

# save final json
with open(output_json_path, "w", encoding="utf-8") as file:
    json.dump(final_dict, file, indent=4, sort_keys = True)

print("json file created")
