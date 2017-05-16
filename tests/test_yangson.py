from yangson.datamodel import DataModel
from yangson.instance import InstanceRoute

module_dir = "../yang-data/"
yang_library_file = "../yang-data/yang-library-data.json"

with open(yang_library_file) as ylfile:
    yl = ylfile.read()
dm = DataModel(yl, [module_dir])


with open("data.json", "rt") as fp:
    json_data = dm.from_raw(json.load(fp))




handler_sn = dm.get_data_node("/dns-server:dns-server-state/zone")
handler_generated = [
    {
        'domain': 'example.com',
        'class': 'IN',
        'server-role': 'master',
        'serial': 2010111201
    }
]

cooked_val = handler_sn.from_raw(handler_generated)

ii_str_abs = "/dns-server:dns-server-state/zone=example.com/class"
ii_abs = dm.parse_resource_id(ii_str_abs)
print("Absolute II: {}".format(ii_abs))

ii_rel = InstanceRoute(ii_abs[2:])
print("Relative II (hardcoded for now): {}".format(ii_rel))

handler_n = handler_sn.orphan_instance(cooked_val)
n_desired = handler_n.goto(ii_rel)
# crashes here
print(n_desired.value)

n = handler_n[0]
print(n.value)

for i in n:
    print(i)
    print(type(i))

