# Imports
import os

# Declare importation paths of nessusaudit.py
if __name__ == "__main__":
    from nessusaudit import *
else:
    from .nessusaudit import *

root_dir = os.getcwd()


# Create Classes
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


def parseTemplate(template_name: str, template_type: str):

    # Convert template to Python objects
    audit_file = NessusAudit(template_name)

    # Defining Variables
    dictionary_fields = dict()
    rules_without_vuln_id = dict()
    rules_list = list()
    rule_index = 0

    # Organising rules into a list consisting of a dictionary with vuln_id as key and rule as value and a dictionary with index as key and rule as value for rules without vuln_id
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

    # Create template object
    template = Template(template_name, audit_file, rules_list, template_type)

    return template


def gen_template(template: Template):

    # Defining Variables
    new_file_content = ""
    index = 0
    line_number = 0

    # Retrieve template path
    template_path = template.template_name

    # Read template file
    with open(template_path, "r") as f:
        file_content = f.readlines()

    # Loop through each line of the template file and get the line content
    while line_number < len(file_content):
        line_content = file_content[line_number]
        # Count the number of spaces the line is indented by
        indentation_count = line_content.count(" ")

        # Check if the line starts with <custom_item> and add the line to the new file content if it doesn't
        if not line_content.strip().startswith("<custom_item>"):
            new_file_content += f"{line_content}"
            line_number += 1
            continue
        # Check if the line starts with <custom_item>
        if line_content.strip().startswith("<custom_item>"):
            # set the indentation of the file before the <custom_item> tag
            new_file_content += f"{' ' * indentation_count}<custom_item>\n"
            # Check if the custom item index count is in the dictionary of rules without vuln_id as key
            if index in template.template_rule_dict[1].keys():
                template_rule_dict_with_index = template.template_rule_dict[1][
                    index].dictionary_fields.dictionary_fields
                # Loop through each key and value in the dictionary and add the key and value to the new file content if the value is not "n/a"
                for key, value in template_rule_dict_with_index.items():
                    if value == "n/a":
                        continue
                    # Check if the key is not "type" and the key does not ends with "required" and add the key and value to the new file content with quotations
                    if key != "type" and key.split("_")[-1] == "required":
                        new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t{value}\n'
                    else:
                        new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t"{value}"\n'
                    line_number += 1
            else:
                # define variables
                content_find_1 = True
                content_find_2 = True
                temp_line_number = line_number

                # Loop through the lines after the <custom_item> tag and before the </custom_item> tag
                while content_find_1 == True or content_find_2 == True:
                    # Retrieve the next line content
                    next_line = file_content[temp_line_number + 1]
                    # Check if the next line starts with reference and retrieve the vuln_id
                    if next_line.strip().startswith("reference"):
                        content_find_1 = False
                        vuln_id = next_line.split("|")[-1].strip().replace(
                            '"', '')
                        # Check if the vuln_id is in the dictionary of rules with vuln_id as key
                        if vuln_id in template.template_rule_dict[0].keys():
                            template_rule_dict_without_index = template.template_rule_dict[
                                0][vuln_id].dictionary_fields.dictionary_fields
                            # Loop through each key and value in the dictionary and add the key and value to the new file content if the value is not "n/a"
                            for key, value in template_rule_dict_without_index.items(
                            ):
                                if value == "n/a":
                                    continue
                                # Check if the key is not "type" and the key does not ends with "required" and add the key and value to the new file content with quotations
                                if key != "type" and key.split(
                                        "_")[-1] == "required":
                                    new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t{value}\n'
                                else:
                                    new_file_content += f'{" " * (indentation_count + 2)}{key}\t:\t"{value}"\n'
                                # Add the line number by 1 to skip this line
                                line_number += 1
                    # Find the </custom_item> tag
                    if next_line.strip().startswith("</custom_item>"):
                        # Define variables once found end of the custom item and setting the line number to continue reading the file from after appending the updated content
                        content_find_2 = False
                        line_number = temp_line_number
                    temp_line_number += 1
            # Increment the written custom item index by 1
            index += 1
        # Increment the line number by 1
        line_number += 1

    # Define output folder path
    output_folder = os.path.join(root_dir, "app", "out-files")
    # Retrieve template name without the file extension and path
    template_name = template_path.split(".")[0].split("\\")[-1].split("/")[-1]

    # Remove existing files if they exist or create folders if they don't exist
    if os.path.isdir(output_folder) and os.path.isdir(
            os.path.join(output_folder, template_name)):
        subdirectory = os.path.join(output_folder, template_name)
        for file in os.listdir(subdirectory):
            os.remove(os.path.join(subdirectory, file))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if not os.path.isdir(os.path.join(output_folder, template_name)):
        os.makedirs(os.path.join(output_folder, template_name))

    # Write the updated template file to the output folder
    with open(
            os.path.join(output_folder, template_name,
                         template_name + "-updated.audit"), "w") as f:
        f.write(new_file_content)
