# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import math
import re

# Find any text between square brackets
square_bracket_regex = re.compile(r"\[[^]]+\]", re.IGNORECASE)
# Find any text between slashes matching /path/to/file
path_to_file_regex = re.compile(r"\/path\/to\/file", re.IGNORECASE)
path_to_file__bracket_regex = re.compile(r"/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/", re.IGNORECASE)
# Find any text between angle brackets
angle_bracket_regex = re.compile(r"<[^>]+>", re.IGNORECASE)
# Find any text which contain a slash
slash_regex = re.compile(r"\/", re.IGNORECASE)
# Find any text which contain an underscore
underscore_regex = re.compile(r"_", re.IGNORECASE)
# Find any text which contain a caret
caret_regex = re.compile(r"\^", re.IGNORECASE)
not_regex_regex = re.compile(r"[a-zA-Z]{1}", re.IGNORECASE)

# Classes

class Guide:
    def __init__(self, guide_name, file_content, stig_rule_dict):
        self.guide_name = guide_name
        self.file_content = file_content
        self.stig_rule_dict = stig_rule_dict

    def __str__(self) -> str:
        return f"{str(self.guide_name)} - {str(self.file_content)} - {str(self.stig_rule_dict)}"

class StigRule:
    def __init__(self, rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_fix_text, rule_description, check_content):
        self.rule_name = rule_name
        self.rule_title = rule_title
        self.vuln_id = vuln_id
        self.rule_id = rule_id
        self.rule_weight = rule_weight
        self.rule_severity = rule_severity
        self.stig_id = stig_id
        self.rule_fix_text = rule_fix_text
        self.rule_description = rule_description
        self.check_content = check_content
        self.category_score = self._calculateScore()
        self.check_commands = self._getRequiredFields(self.check_content)
        self.fix_commands = self._getRequiredFields(self.rule_fix_text)

    def _getRequiredFields(self, field):
        command_list = []
        
        field_split = field.split("\n")
        for field_line in field_split:
            field_text_to_fill = []
    
            if not field_line.startswith("$ "):
                continue

            field_command = field_line.replace("$ ", "").strip()

            if path_to_file__bracket_regex.findall(field_command):
                for command in path_to_file__bracket_regex.findall(field_command):
                    field_text_to_fill.append(command)
            else:
                for command in square_bracket_regex.findall(field_command):
                    field_text_to_fill.append(command)

            for command in path_to_file_regex.findall(field_command):
                field_text_to_fill.append(command)
                
            for command in angle_bracket_regex.findall(field_command):
                field_text_to_fill.append(command)

            new_command = Command(field_command, field_text_to_fill)
            command_list.append(new_command)

        return command_list
  

    def _calculateScore(self):
        severity_Dictionary = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "no": 1,
        }

        severity_categories_dictionary = {
            "undefined": -1,
            "Very Low": 3,
            "Low": 5,
            "Medium": 10,
            "High": 13,
            "Very High": 17,
            "Extreme": float("inf"),
        }

        try:
            category_score = float(math.ceil(float(severity_Dictionary[self.rule_severity]) * (float(self.rule_weight)/2)))

            for category_name, category_score_limit in severity_categories_dictionary.items():
                if category_score <= category_score_limit:
                    severity_category = category_name
                    break
            self.category_score = severity_category
        except:
            self.category_score = "undefined"
    
        return self.category_score

    def __str__(self) -> str:
        return f"{str(self.rule_name)} - {str(self.rule_title)} - {str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_weight)} - {str(self.rule_severity)} - {str(self.stig_id)} - {str(self.rule_fix_text)} - {str(self.rule_description)} - {str(self.check_content)} - {str(self.category_score)}"


class Command:
    def __init__(self, command, replacements):
        self.command = command
        self.replacements = replacements

    def replaceCommand(self, target_replacements):
        new_command = self.command
        for replacement_key in self.replacements:
            if replacement_key in target_replacements:
                replacement_value = target_replacements[replacement_key]
                new_command = new_command.replace(replacement_key, replacement_value)
            else:
                print(f"Replacement Key: {replacement_key} not found in target_replacements")
        
        return new_command
    
    def __repr__(self) -> str:
        return f"Command({str(self.command)} - {str(self.replacements)})"


class RuleInput:

    def __init__(self, vuln_id, enabled, check_replacement, fix_replacement):
        self.vuln_id = vuln_id
        self.enabled = enabled
        self.check_replacement = check_replacement
        self.fix_replacement = fix_replacement

    def __str__(self) -> str:
        return f"{str(self.vuln_id)} - {str(self.enabled)} - {str(self.check_replacement)} - {str(self.fix_replacement)}"

# Functions not within a class

def parseGuide(filename):
    # Defining Variables
    rule_dictionary = {}

    # Open XML File
    with open(filename, 'r', encoding='utf-8') as xml_file:
        xml_data = xml_file.read()
        content = BeautifulSoup(xml_data, 'xml')

    # Find all Group tags with the id attribute
    group_id_tags = content.find_all('Group', id=True)

    # Populate StigRule Object
    for group_id_tag in group_id_tags:

        # Extract Group ID
        group_id = group_id_tag['id']

        # Extract Group Information
        group_info = content.find('Group', id=group_id)
        
        # Extract Information under the parent Group tag
        rule_name = group_info.find('title').text
        vuln_id = group_id

        # Extract Rule Information
        group_rule_info = group_info.find('Rule')
        rule_id = group_rule_info['id']
        rule_weight = group_rule_info['weight']
        rule_severity = group_rule_info['severity']
        rule_title = group_rule_info.find('title').text
        stig_id = group_rule_info.find('version').text
        rule_fix_text = group_rule_info.find('fixtext').text
        # Extract Rule Description
        group_description_info = group_rule_info.find('description').text
        # URL Decode Rule Description
        group_description_info_decoded = unquote(group_description_info)
        # Transform back into XML
        group_description_info_xml = BeautifulSoup(group_description_info_decoded, 'xml')
        rule_description = group_description_info_xml.find('VulnDiscussion').text

        # Extract Check Information from Rule Information
        check_rule_info = group_rule_info.find('check')
        check_content = check_rule_info.find('check-content').text

        # Create Object
        rule = StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_fix_text, rule_description, check_content)
        rule_dictionary[vuln_id] = rule
    
    # Create Guide Object
    guide = Guide(filename, group_id_tags, rule_dictionary)

    return guide

def createScript(guide, user_input):
    check_script = "#!/bin/bash" + "\n" + "mkdir AdminGuard" + "\n" + "cd AdminGuard" + "\n" + "touch check_script_logs.txt" + "\n"
    fix_script = "#!/bin/bash" + "\n" + "mkdir AdminGuard" + "\n" + "cd AdminGuard" + "\n" + "touch fix_script_logs.txt" + "\n"

    for vuln_id in user_input.keys():
        if vuln_id in guide.stig_rule_dict.keys():
            target_rule = guide.stig_rule_dict[vuln_id]
            if "check" in user_input[vuln_id]:
                check_inputs = user_input[vuln_id]["check"]
                for check_command, replacement_dict in zip(target_rule.check_commands, check_inputs):
                    parsed_command = check_command.replaceCommand(replacement_dict)
                    check_script += "echo " + parsed_command + " >> check_script_logs.txt" + "\n"
                    check_script += parsed_command + " >> check_script_logs.txt" + "\n"
            if "fix" in user_input[vuln_id]:
                fix_inputs = user_input[vuln_id]["fix"]
                for fix_command, replacement_dict in zip(target_rule.fix_commands, fix_inputs):
                    parsed_command = fix_command.replaceCommand(replacement_dict)
                    fix_script += "echo " + parsed_command + " >> fix_script_logs.txt" + "\n"
                    fix_script += parsed_command + " >> fix_script_logs.txt" + "\n"

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0]
    with open(guide_file_name + " - " + "CheckScript.sh", "w") as linux_check_script:
        linux_check_script.write(check_script)
    with open(guide_file_name + " - " + "FixScript.sh", "w") as linux_fix_script:
        linux_fix_script.write(fix_script)

# user_input = {
#     "V-230309": {
#         "check": [
#             {'[PART]': 'yum', '[Test]': 'install'},
#             {'<file>': 'woo'}
#         ],

#         "fix": [{}],    
#     },
# }


# guide = parseGuide("./script/testXmlFiles/U_RHEL_8_STIG_V1R11_Manual-xccdf.xml")

# print(createScript(guide, user_input))
