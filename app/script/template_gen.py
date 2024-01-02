# Imports
import os

if __name__ == "__main__":
    from nessusaudit import *
else:
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

    def __init__(self, vuln_id: str, dictionary_fields: dict):
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


def parseTemplate(template_name: str, template_type: str):

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

    template = Template(template_name, audit_file, rules_list, template_type)

    return template


def gen_template(template: Template):
    template_name = template.template_name
    new_file_content = ""
    index = 0
    line_number = 0
    with open(template_name, "r") as f:
        file_content = f.readlines()
    while line_number < len(file_content):
        line_content = file_content[line_number]
        indentation_count = line_content.count(" ")
        if not line_content.strip().startswith("<custom_item>"):
            new_file_content += f"{line_content}"
            line_number += 1
            continue
        if line_content.strip().startswith("<custom_item>"):
            new_file_content += f"{' ' * indentation_count}<custom_item>\n"
            if index in template.template_rule_dict[1].keys():
                template_rule_dict_with_index = template.template_rule_dict[1][
                    index].dictionary_fields.dictionary_fields
                for key, value in template_rule_dict_with_index.items():
                    if value == "n/a":
                        continue
                    if key != "type" and key.split("_")[-1] == "required":
                        new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t{value}\n'
                    else:
                        new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t"{value}"\n'
                    line_number += 1
            else:
                content_find_1 = True
                content_find_2 = True
                temp_line_number = line_number
                while content_find_1 == True or content_find_2 == True:
                    next_line = file_content[temp_line_number + 1]
                    if next_line.strip().startswith("reference"):
                        content_find_1 = False
                        vuln_id = next_line.split("|")[-1].strip().replace(
                            '"', '')
                        if vuln_id  in template.template_rule_dict[0].keys():
                            template_rule_dict_without_index = template.template_rule_dict[
                                0][vuln_id].dictionary_fields.dictionary_fields
                            for key, value in template_rule_dict_without_index.items(
                            ):
                                if value == "n/a":
                                    continue
                                if key != "type" and key.split(
                                        "_")[-1] == "required":
                                    new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t{value}\n'
                                else:
                                    new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t"{value}"\n'
                                line_number += 1
                    if next_line.strip().startswith("</custom_item>"):
                        content_find_2 = False
                        line_number = temp_line_number
                    temp_line_number += 1
            index += 1
        line_number += 1
    
    output_folder = os.path.join(root_dir, "app", "out-files")
    template_name = template_name.split(".")[0].split("\\")[-1]

    # Remove existing files if they exist or create folders if they don't exist
    if os.path.isdir(output_folder) and os.path.isdir(
            os.path.join(output_folder, template_name)):
        subdirectory = os.path.join(output_folder, template_name)
        for file in os.listdir(subdirectory):
            os.remove(os.path.join(subdirectory, file))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if not os.path.isdir(os.path.join(output_folder, template_name)):
        os.chdir(output_folder)
        os.mkdir(template_name)
        os.chdir(root_dir)

    with open(
            os.path.join(
                output_folder, template_name, template_name + "-updated.audit"),
            "w") as f:
        f.write(new_file_content)
