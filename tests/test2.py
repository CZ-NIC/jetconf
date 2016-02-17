from yangson import DataModel
module_dir = "/Users/lhotka/Projects/jetconf/yang"
with open("/Users/lhotka/Projects/jetconf/data/yang-library-data.json",
          encoding="utf-8") as infile:
    txt = infile.read()
    dm = DataModel.from_yang_library(txt, module_dir)
    nacm = dm.get_schema_node("/ietf-netconf-acm:nacm")
    print(nacm.default_deny)
    rpcname = dm.get_data_node("/ietf-netconf-acm:nacm/rule-list/rule/rpc-name")
    print(rpcname)
