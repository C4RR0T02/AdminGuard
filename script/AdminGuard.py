# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import math
import re
import logging
import os

# Find any text between square brackets
square_bracket_regex = re.compile(r"\[.*\]", re.IGNORECASE)
# Find any text between slashes matching /path/to/file
path_to_file_regex = re.compile(r"\/path\/to\/file", re.IGNORECASE)
# Find any text between angle brackets
angle_bracket_regex = re.compile(r"<.*>", re.IGNORECASE)
# Find any text which contain a slash
slash_regex = re.compile(r"\/", re.IGNORECASE)
# Find any text which contain an underscore
underscore_regex = re.compile(r"_", re.IGNORECASE)
# Find any text which contain a caret
caret_regex = re.compile(r"\^", re.IGNORECASE)

# Classes

class Guide:
    def __init__(self, guide_name, file_content, stig_rule_list):
        # @guide_name: Name of the guide
        # @file_content: Content of the guide
        # @stig_rule_list: List of all the rules in the guide

        self.guide_name = guide_name
        self.file_content = file_content
        self.stig_rule_list = stig_rule_list

    def __str__(self) -> str:
        return f"{str(self.guide_name)} - {str(self.file_content)} - {str(self.stig_rule_list)}"

class StigRule():
    def __init__(self, rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_fix_text, rule_description, check_content):
        # @rule_name: Name of the rule
        # @rule_title: Title of the rule
        # @vuln_id: Vuln ID of the rule
        # @rule_id: Rule ID of the rule
        # @rule_weight: Rule Weight of the rule
        # @rule_severity: Rule Severity of the rule
        # @stig_id: STIG ID of the rule
        # @rule_fix_text: Rule Fix Text of the rule
        # @rule_description: Rule Description of the rule
        # @check_content: Check Content of the rule
        # @category_score: Category Score of the rule

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
        self.category_score = "undefined"

    def calculateScore(self):
        # Defining Variables
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
            # Converting severity to the score to calculate the category
            # Severity * (Weight/2) = Category Score
            # @Serverity: Critical = 5, High = 4, Medium = 3, Low = 2, No = 1
            # @Weight: 1-10
            category_score = float(math.ceil(float(severity_Dictionary[self.rule_severity]) * (float(self.rule_weight)/2)))

            # Assign Category based on the calulated score
            for category_name_dictionary, category_score_limit_dictionary in severity_categories_dictionary.items():
                if category_score <= category_score_limit_dictionary:
                    severity_category = category_name_dictionary
                # Assign Category Score back to object
                self.category_score = severity_category
        except:
            # Return an undefined value if the score cannot be calculated
            self.category_score = "undefined"
    
        return self.category_score
    
    # def __str__(self) -> str:
    #     return f"{str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_severity)}"

    def __str__(self) -> str:
        return f"{str(self.rule_name)} - {str(self.rule_title)} - {str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_weight)} - {str(self.rule_severity)} - {str(self.stig_id)} - {str(self.rule_fix_text)} - {str(self.rule_description)} - {str(self.check_content)} - {str(self.category_score)}"


class RuleInput():

    def __init__(self, vuln_id, enabled, check_replacement, fix_replacement):
        # @vuln_id: Vuln ID of the rule
        # @enabled: Status if the rule is enabled
        # @check_replacement: Replacement for the check content
        # @fix_replacement: Replacement for the fix text

        self.vuln_id = vuln_id
        self.enabled = enabled
        self.check_replacement = check_replacement
        self.fix_replacement = fix_replacement

    def __str__(self) -> str:
        return f"{str(self.vuln_id)} - {str(self.enabled)} - {str(self.check_replacement)} - {str(self.fix_replacement)}"

# Functions not within a class

def parseGuide(filename):
    # Defining Variables
    rule_list = []

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
            rule_list.append(StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_fix_text, rule_description, check_content))
        
        # Create Guide Object
        guide = Guide(filename, group_id_tags, rule_list)

        # Calculate Category Score for each rule
        for rule in rule_list:
            rule.calculateScore()

    return guide

def getCommands(field):
    try: 
        # Defining Variables
        command_list = []
        # Splitting the field into lines
        field_split = field.split("\n")
        # Extracting the commands from the field
        for field_line in field_split:
            # Check if the line starts with a '$ ' character
            if field_line.startswith("$ "):
                # Remove the '$ ' character from the line
                field_command = field_line.replace("$ ", "")
                # Append the command to the command list
                command_list.append(field_command)
        # Return the command list
        return command_list
    except:
        # Return an error message if the commands cannot be extracted
        return "An error occured while extracting the commands from the" + str(field) + "field."

def getUserInputToFill(command_list):
        # Defining Variables
        user_input_fields = []
        field_text_to_fill = ""

        # Looping all commands in command_list
        for command in command_list:
            # Extracting the fields from the command
            # Find the text between square brackets
            if square_bracket_regex.search(command):
                # Grab the text matching the pattern
                field_text_to_fill = square_bracket_regex.search(command).group()
                # Remove the square brackets from the text
                field_text_to_fill = re.sub(r"[\[\]]", "", field_text_to_fill)

                # TODO: Find a better logic for the filtering out of possible regex
                if not caret_regex.search(field_text_to_fill):
                    # Replace slashes with spaces
                    if slash_regex.search(field_text_to_fill):
                        field_text_to_fill = field_text_to_fill.replace("/", " ")
                    # Replace underscores with spaces
                    if underscore_regex.search(field_text_to_fill):
                        field_text_to_fill = field_text_to_fill.replace("_", " ")
            
            # Find the pattern /path/to/file
            if path_to_file_regex.search(command):
                # Grab the text matching the pattern
                field_text_to_fill = path_to_file_regex.search(command).group()
                # Replace slashes with spaces
                field_text_to_fill = field_text_to_fill.replace("/", " ")

            # Find the text between angle brackets
            if angle_bracket_regex.search(command):
                # Grab the text matching the pattern
                field_text_to_fill = angle_bracket_regex.search(command).group()
                # Remove the angle brackets from the text
                field_text_to_fill = re.sub(r"[<>]", "", field_text_to_fill)
            
            # Check if the field_text_to_fill is longer than 3 characters
            if len(field_text_to_fill) > 3:
                # Append the field_text_to_fill to the user_input_fields list
                user_input_fields.append(field_text_to_fill)
            else:
                # Append an empty string to the user_input_fields list as it is likely a regex
                user_input_fields.append("")
        return user_input_fields

def replaceUserInputOfCommand(command_list, user_input):
    # Defining Variables
    new_command_list = []

    # Looping through the command_list and user_input
    for command, input in zip(command_list, user_input):
        # Replace the text in the command with the user input if it meets the criteria
        # Find the text between square brackets
        if square_bracket_regex.search(command) and len(re.sub(r"[\[\]]", "", square_bracket_regex.search(command).group())) > 3:
            command = square_bracket_regex.sub(input, command)
        # Find the pattern /path/to/file
        if path_to_file_regex.search(command):
            command = path_to_file_regex.sub(input, command)
        # Find the text between angle brackets
        if angle_bracket_regex.search(command) and len(angle_bracket_regex.search(command).group()) > 3:
            command = angle_bracket_regex.sub(input, command)
        # Append the command to the new_command_list
        new_command_list.append(command)
    return new_command_list

def createScriptFromRules(rules, rule_input_list):
    # Defining Variables
    check_script = "#!/bin/bash" + "\n" + "mkdir AdminGuard" + "\n" + "cd AdminGuard" + "\n" + "touch check_script_logs.txt" + "\n"
    fix_script = "#!/bin/bash" + "\n" + "mkdir AdminGuard" + "\n" + "cd AdminGuard" + "\n" + "touch fix_script_logs.txt" + "\n"
    user_check_command_list = []
    user_fix_command_list = []

    for rule, rule_input in zip(rules, rule_input_list):
        # Check if the rule is enabled
        if rule_input.enabled == True:
            user_check_command_list = replaceUserInputOfCommand(getCommands(rule.check_content), rule_input.check_replacement)
            user_fix_command_list = replaceUserInputOfCommand(getCommands(rule.rule_fix_text), rule_input.fix_replacement)
        # TODO: Fix the logic below
        for check_command in user_check_command_list:
            if len(check_command) != 0:
                check_script += check_command + " >> check_script_logs.txt" + "\n"
        for fix_command in user_fix_command_list:
            if len(fix_command) != 0:
                fix_script += fix_command + " >> fix_script_logs.txt" + "\n"

    with open(guide.guide_name.split("/")[-1].split(".")[0] + " - " + "CheckScript.sh", "w") as linux_check_script:
        linux_check_script.write(check_script)
    with open(guide.guide_name.split("/")[-1].split(".")[0] + " - " + "FixScript.sh", "w") as linux_fix_script:
        linux_fix_script.write(fix_script)
    return linux_check_script, linux_fix_script

def getRequiredInput(rule_list):
    for rule in rule_list:
        inputs_check_required = getUserInputToFill(getCommands(rule.check_content))
        inputs_fix_required = getUserInputToFill(getCommands(rule.rule_fix_text))
    return inputs_check_required, inputs_fix_required

def getUserInputFromSite(inputs_check, inputs_fix, enable_choice):
    rule_input_list = []
    for rule, input_check, input_fix, enable in zip(guide.stig_rule_list, inputs_check, inputs_fix, enable_choice):
        if enable:
            rule_input_list.append(RuleInput(rule.vuln_id ,True, input_check, input_fix))
        else:
            rule_input_list.append(RuleInput(rule.vuln_id ,False, "", ""))
    return rule_input_list

# Main
guide = parseGuide("./script/testXmlFiles/U_RHEL_8_STIG_V1R11_Manual-xccdf.xml")

user_check_input = ["Hello", "World", "Test", "Test2", "World", "Test", "Test2", "World", "Test", "Test2"]
user_fix_input = ["Hello", "World", "Test", "Test2", "World", "Test", "Test2", "World", "Test", "Test2"]
user_enable_list = [True, True, True, True, True, True, True, True, False, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

get_required_field = getRequiredInput(guide.stig_rule_list)

rule_input_list = getUserInputFromSite(user_check_input, user_fix_input, user_enable_list)

createScriptFromRules(guide.stig_rule_list, rule_input_list)

# Links to external sites used

# PYTHON DOCUMENTATIONS
# XML Manipulation - https://www.crummy.com/software/BeautifulSoup/bs4/doc/
# File Manipulation - https://www.digitalocean.com/community/tutorials/python-read-file-open-write-delete-copy

# REGEX
# Regex - https://docs.python.org/3/library/re.html
# Regex Generator - https://regex-generator.olafneumann.org/?sampleText=&flags=Pi
# Regex Checker - https://regex101.com/r/NYVFkU/1

# CHATGPT
# ChatGPT - https://chat.openai.com/

# STIG
# STIG Red Hat Enterprise Linux 8 STIG - Ver 3, Rel 12 - https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V1R11_STIG.zip
# STIG Windows Server 2022 - Ver 1, Rel 3 - https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R3_STIG.zip 
# STIG Viewer - https://public.cyber.mil/stigs/srg-stig-tools/ 
