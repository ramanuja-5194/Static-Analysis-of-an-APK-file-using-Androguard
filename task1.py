import sys
import json
from androguard.misc import AnalyzeAPK

arguments = sys.argv

if len(arguments) != 3:
    print("Incorrect input format")
    print("Correct format: python task1.py input_file_path output_json_path")

input_file_path = arguments[1]
output_json_path = arguments[2]

# analyze apk to get manifest and dalvik objects
apk_obj, dalvik_obj, analysis_obj = AnalyzeAPK(input_file_path)

# extract package name
Package_name = apk_obj.get_package()

# extract activities and count
Activities = apk_obj.get_activities()
Activities_count = len(Activities)

# extract services and count
Services = apk_obj.get_services()
Services_count = len(Services)

# extract receivers and count
Receivers = apk_obj.get_receivers()
Receivers_count = len(Receivers)

# extract content providers and count
Content_providers = apk_obj.get_providers()
Content_providers_count = len(Content_providers)

# dictionary for manifest components
dict_1 = {
    "package_name" : Package_name,
    "activities" : Activities,
    "activities_count" : Activities_count,
    "services" : Services,
    "services_count" : Services_count,
    "receivers" : Receivers,
    "receivers_count" : Receivers_count,
    "content_providers" : Content_providers,
    "content_providers_count" : Content_providers_count
}

print("dict_1 created")

# extract permissions and classify into aosp vs third party
permissions = apk_obj.get_permissions()

AOSP_list = []
third_part_list = []

for per in permissions:
    if per.startswith("android.permission."):
        AOSP_list.append(per)
    else: 
        third_part_list.append(per)

dict_2 = {
    "AOSP_permissions" : AOSP_list,
    "AOSP_permissions_count" : len(AOSP_list),
    "third-party_permissions" : third_part_list,
    "third-party_permissions_count" : len(third_part_list)
}

print("dict_2 created")

# extract hardware features
hardware_features = apk_obj.get_features()

# extract intent filters for activities, services, receivers
Intent_filters = {}

components = {
    "activity" : Activities,
    "service" : Services,
    "receiver" : Receivers
}

for comp_type, comp_list in components.items():
    for name in comp_list:
        filters = apk_obj.get_intent_filters(comp_type, name)
        if filters:
            Intent_filters[name] = filters

dict_3 = {
    "hardware_features" : hardware_features,
    "intent_filters" : Intent_filters
}

print("dict_3 created")

# merge all dictionaries
dict_final = dict_1 | dict_2 | dict_3

# sort lists inside final dict
for key,val in dict_final.items():
    if isinstance(val, list):
        dict_final[key] = sorted(val)

# save final json
with open(output_json_path, "w", encoding="utf-8") as file:
    json.dump(dict_final, file, indent=4, sort_keys = True)
