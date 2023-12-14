# Imports
import os
import re
from .nessusaudit import *

root_dir = os.getcwd()

class Template:

    def __init__(self, template_name: str, file_content: list,
                 template_rule_dict: dict, guide_type: str):
        self.template_name = template_name
        self.file_content = file_content
        self.template_rule_dict = template_rule_dict
        self.guide_type = guide_type
    
    def __str__(self) -> str:
        return f"{self.template_name} : {self.file_content} : {self.template_rule_dict} : {self.guide_type}"
    
class RuleItems:

    def __init__(self, vuln_id, dictionary_fields):
        self.vuln_id = vuln_id

        self.dictionary_fields = dictionary_fields
    
    def replaceTemplateFields(self, field: str, replacement: dict):
        field_data = self.field
        if field_data is None:
            self.field = field_data
        else:
            self.field = replacement

    def __str__(self) -> str:
        return f"{str(self.dictionary_fields)}"

class RuleTemplateInput:

    def __init__(self, vuln_id: str, replacement: dict):
        self.vuln_id = vuln_id
        self.replacement = replacement

    def __str__(self) -> str:
        return f"{self.vuln_id} : {self.replacement}"

def parseTemplate(template_name, guide_type):

    audit_file = NessusAudit(template_name)
    dictionary_fields = dict()
    rules_without_vuln_id = dict()
    rules_list = list()
    rule_index = 0

    for rule in audit_file.array():
        rule_reference = rule['reference']
        vuln_id = rule_reference.split("|")[-1]
        rule_object = RuleItems(vuln_id, rule)
        if vuln_id == "n/a":
            rules_without_vuln_id[rule_index] = RuleItems(vuln_id, rule_object)
        else:
            dictionary_fields[vuln_id] = RuleItems(vuln_id, rule_object)
        rule_index += 1

    rules_list.append(dictionary_fields)
    rules_list.append(rules_without_vuln_id)

    template = Template(template_name, audit_file, rules_list, guide_type)

    return template

# template = parseTemplate("./app/tests/testFiles/DISA_STIG_Red_Hat_Enterprise_Linux_8_v1r11.audit", "Linux")
# # print(template.template_rule_dict[0].values())
# # print(template.template_rule_dict[0].keys())
# for vuln_id in template.template_rule_dict[0].keys():
#     rule = template.template_rule_dict[0][vuln_id].dictionary_fields.dictionary_fields.keys()
#     # for array_value in rule:
#     print(rule)
#     break
