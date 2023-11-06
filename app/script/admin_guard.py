# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import math
import os
import re

# Find any text between square brackets
square_bracket_regex = re.compile(r"\[[^]]+\]", re.IGNORECASE)
# Find any text between slashes matching /path/to/file
path_to_file_regex = re.compile(r"\/path\/to\/file", re.IGNORECASE)
path_to_file_bracket_regex = re.compile(
    r"/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/", re.IGNORECASE)
# Find any text between angle brackets
angle_bracket_regex = re.compile(r"<[^>]+>", re.IGNORECASE)
# Find any text which contain a slash
slash_regex = re.compile(r"\/", re.IGNORECASE)
# Find any text which contain an underscore
underscore_regex = re.compile(r"_", re.IGNORECASE)
# Find any text which contain a caret
caret_regex = re.compile(r"\^", re.IGNORECASE)
not_regex_regex = re.compile(r"[a-zA-Z]{1}", re.IGNORECASE)


class Guide:

    def __init__(self, guide_name, file_content, stig_rule_dict, guide_type):
        self.guide_name = guide_name
        self.file_content = file_content
        self.stig_rule_dict = stig_rule_dict
        self.guide_type = guide_type

    def __str__(self) -> str:
        return f"{str(self.guide_name)} - {str(self.file_content)} - {str(self.stig_rule_dict)}"


class StigRule:

    def __init__(self, rule_name, rule_title, vuln_id, rule_id, rule_weight,
                 rule_severity, stig_id, rule_fix_text, rule_description,
                 check_content):
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
        self.check_commands = ''
        self.fix_commands = ''

    def _getRequiredFields(self, type, field):
        if type == "Linux":
            command_list = []
            field_split = field.split("\n")
            for field_line in field_split:

                field_line = field_line.strip()

                if not field_line.startswith("$ "):
                    continue

                field_command = field_line.replace("$ ", "")

                command_list.append(field_command)
            return command_list

        if type == "Windows":
            command_list = []
            powershell_command_list = getPowerShellCommands()

            field_split = field.split("\n")
            for field_line in field_split:
                field_command = ""

                if not field_line.startswith(
                        'Enter "') or field_line.startswith("Enter '"):
                    continue

                if field_line.startswith('Enter "') or field_line.startswith(
                        "Enter '"):
                    if 'Enter "q" at the' in field_line:
                        continue
                    field_command = field_line.replace('Enter "', "").replace(
                        "Enter '", "").strip()
                    line_end_index = field_command.rfind('"')
                    if line_end_index != -1:
                        field_command = field_command[:line_end_index]
                    line_end_index = field_command.rfind("'")
                    if line_end_index != -1:
                        field_command = field_command[:line_end_index]

                for powershell_command in powershell_command_list:
                    if powershell_command.startswith("# "):
                        continue
                    if not field_line.startswith(powershell_command):
                        continue
                    field_command = field_line.strip()
                    if field_command.endswith('.'):
                        field_command = field_command[:-1]

                command_list.append(field_command)
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
            category_score = float(
                math.ceil(
                    float(severity_Dictionary[self.rule_severity]) *
                    (float(self.rule_weight) / 2)))
                    
            for category_name, category_score_limit in severity_categories_dictionary.items(
            ):
                if category_score >= category_score_limit:
                    severity_category = category_name
            self.category_score = severity_category
        except Exception:
            self.category_score = "undefined"

        return self.category_score

    def replaceFields(self, field, replacement):
        field_data = self.field
        if field_data is None:
            self.field = field_data
        else:
            self.field = replacement

    def __str__(self) -> str:
        return f"{str(self.rule_name)} - {str(self.rule_title)} - {str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_weight)} - {str(self.rule_severity)} - {str(self.stig_id)} - {str(self.rule_fix_text)} - {str(self.rule_description)} - {str(self.check_content)} - {str(self.category_score)}"

class RuleInput:

    def __init__(self, vuln_id, check_replacement, fix_replacement):
        self.vuln_id = vuln_id
        self.check_replacement = check_replacement
        self.fix_replacement = fix_replacement

    def __str__(self) -> str:
        return f"{str(self.vuln_id)} - {str(self.check_replacement)} - {str(self.fix_replacement)}"


def getPowerShellCommands():
    current_directory = os.getcwd()
    filepath = os.path.join(current_directory, 'app', 'script',
                            'powershell_commands.txt')
    with open(filepath, 'r', encoding='utf-8') as powershell_command_file:
        powershell_commands = powershell_command_file.read().splitlines()
    return powershell_commands


def parseGuide(filename, guide_type):
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
        group_description_info_xml = BeautifulSoup(
            group_description_info_decoded, 'xml')
        rule_description = group_description_info_xml.find(
            'VulnDiscussion').text

        # Extract Check Information from Rule Information
        check_rule_info = group_rule_info.find('check')
        check_content = check_rule_info.find('check-content').text

        # Create Object
        rule = StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight,
                        rule_severity, stig_id, rule_fix_text,
                        rule_description, check_content)
        rule.check_commands = rule._getRequiredFields(guide_type,
                                                      check_content)
        rule.fix_commands = rule._getRequiredFields(guide_type, rule_fix_text)
        rule_dictionary[vuln_id] = rule

    # Create Guide Object
    guide = Guide(filename, group_id_tags, rule_dictionary, guide_type)

    return guide


def linuxCreateScript(guide, user_input):

    output_folder = os.path.join(os.getcwd(), "app", "out-files")
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]

    check_script = """#!/bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt
touch manual_check.txt

run_command() {
    local cmd="$1"
    local description="$2"

    output=$(eval "$cmd" 2>&1)
    if [ $? -ne 0 ]; then
        echo "Error while running $description"
        echo "Error while running $description" >> error_logs.txt
    fi
}
"""

    fix_script = """#!/bin/bash
mkdir AdminGuard
cd AdminGuard
touch fix_script_logs.txt
touch manual_fix.txt

run_command() {
    local cmd="$1"
    local description="$2"

    output=$(eval "$cmd" 2>&1)
    if [ $? -ne 0 ]; then
        echo "Error while running $description"
        echo "Error while running $description" >> error_logs.txt
    fi
}
"""

    manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    with open(output_folder + "/" + guide_file_name + "-" + "ManualCheck.txt",
              "ab") as linux_manual_check:
        linux_manual_check.write(manual_check.encode())

    with open(output_folder + "/" + guide_file_name + "-" + "ManualFix.txt",
              "ab") as linux_manual_fix:
        linux_manual_fix.write(manual_fix.encode())

    if len(user_input) == 0:
        with open(
                output_folder + "/" + guide_file_name + "-" + "CheckScript.sh",
                "wb") as linux_check_script:
            linux_check_script.write(check_script.encode())
        with open(output_folder + "/" + guide_file_name + "-" + "FixScript.sh",
                  "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())

    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_check_input = user_input[vuln_id]["check"]
        if len(target_rule.check_commands) == 0:
            check_script += "echo 'Manual check required for" + vuln_id + "' >> check_script_logs.txt" + "\n"
            manual_check = vuln_id + "\n" + target_rule.check_content + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "-" +
                    "ManualCheck.txt", "ab") as linux_manual_check:
                linux_manual_check.write(manual_check.encode())

        for check_cmd_index, check_cmd in enumerate(
                target_rule.check_commands):
            replacement_dict = user_check_input.get(check_cmd_index, None)
            if not replacement_dict:
                if check_cmd.replacements:
                    raise Exception(
                        f"Missing check replacement values for {check_cmd.command}"
                    )
                parsed_command = check_cmd.command
            else:
                parsed_command = check_cmd.replaceCommand(replacement_dict)

            check_script = check_script + "echo " + parsed_command + " >> check_script_logs.txt" + "\n"
            check_script = check_script + "run_command '" + parsed_command + " >> check_script_logs.txt' 'Check Script for " + vuln_id + "'" + "\n"

        with open(
                output_folder + "/" + guide_file_name + "-" + "CheckScript.sh",
                "wb") as linux_check_script:
            linux_check_script.write(check_script.encode())

    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_fix_input = user_input[vuln_id]["fix"]
        if len(target_rule.fix_commands) == 0:
            fix_script += "echo 'Manual fix required for" + vuln_id + "' >> fix_script_logs.txt" + "\n"
            manual_fix = vuln_id + "\n" + target_rule.rule_fix_text + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "-" +
                    "ManualFix.txt", "ab") as linux_manual_fix:
                linux_manual_fix.write(manual_fix.encode())
        for fix_cmd_index, fix_cmd in enumerate(target_rule.fix_commands):
            replacement_dict = user_fix_input.get(fix_cmd_index, None)
            if not replacement_dict:
                if fix_cmd.replacements:
                    raise Exception(
                        f"Missing check replacement values for {fix_cmd.command}"
                    )
                parsed_command = fix_cmd.command
            else:
                parsed_command = fix_cmd.replaceCommand(replacement_dict)

            fix_script += "echo " + parsed_command + " >> fix_script_logs.txt" + "\n"
            fix_script += "run_command '" + parsed_command + " >> fix_script_logs.txt' 'Fix Script for " + vuln_id + "'" + "\n"
        with open(output_folder + "/" + guide_file_name + "-" + "FixScript.sh",
                  "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())


def windowsCreateScript(guide, user_input):

    output_folder = os.path.join(os.getcwd(), "app", "out-files")
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]

    check_script = """mkdir AdminGuard | out-null
Set-Location AdminGuard
New-Item -Name 'check_script_logs.txt' -ItemType 'file' | out-null
New-Item -Name 'manual_check.txt' -ItemType 'file' | out-null

function run_command {
    param (
        [string]$cmd,
        [string]$description
    )

    $output = Invoke-Expression $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error while running $description"
        "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
    }
}
"""

    fix_script = """mkdir AdminGuard | out-null
Set-Location AdminGuard
New-Item -Name 'fix_script_logs.txt' -ItemType 'file' | out-null
New-Item -Name 'manual_fix.txt' -ItemType 'file' | out-null

function run_command {
    param (
        [string]$cmd,
        [string]$description
    )

    $output = Invoke-Expression $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error while running $description"
        "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
    }
}
"""

    manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    with open(output_folder + "/" + guide_file_name + "-" + "ManualCheck.txt",
              "ab") as windows_manual_check:
        windows_manual_check.write(manual_check.encode())

    with open(output_folder + "/" + guide_file_name + "-" + "ManualFix.txt",
              "ab") as windows_manual_fix:
        windows_manual_fix.write(manual_fix.encode())

    if len(user_input) == 0:
        with open(
                output_folder + "/" + guide_file_name + "-" +
                "CheckScript.ps1", "wb") as windows_check_script:
            windows_check_script.write(check_script.encode())
        with open(
                output_folder + "/" + guide_file_name + "-" + "FixScript.ps1",
                "wb") as windows_fix_script:
            windows_fix_script.write(fix_script.encode())

    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_check_input = user_input[vuln_id]["check"]
        if len(target_rule.check_commands) == 0:
            check_script += "Write-Output 'Manual check required for" + vuln_id + "' >> check_script_logs.txt" + "\n"
            manual_check = vuln_id + "\n" + target_rule.check_content + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "-" +
                    "ManualCheck.txt", "ab") as windows_manual_check:
                windows_manual_check.write(manual_check.encode())
        for check_cmd_index, check_cmd in enumerate(
                target_rule.check_commands):
            replacement_dict = user_check_input.get(check_cmd_index, None)
            if not replacement_dict:
                if check_cmd.replacements:
                    raise Exception(
                        f"Missing check replacement values for {check_cmd.command}"
                    )
                parsed_command = check_cmd.command
            else:
                parsed_command = check_cmd.replaceCommand(replacement_dict)

            check_script += "Write-Output '" + parsed_command + "' >> check_script_logs.txt" + "\n"
            check_script += "run_command " + "'" + parsed_command + " >> check_script_logs.txt' 'Check Script for " + vuln_id + "'" + "\n"

        with open(
                output_folder + "/" + guide_file_name + "-" +
                "CheckScript.ps1", "wb") as windows_check_script:
            windows_check_script.write(check_script.encode())

    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_fix_input = user_input[vuln_id]["fix"]
        if len(target_rule.fix_commands) == 0:
            fix_script += "Write-Output 'Manual fix required for" + vuln_id + "' >> fix_script_logs.txt" + "\n"
            manual_fix = vuln_id + "\n" + target_rule.rule_fix_text + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "-" +
                    "ManualFix.txt", "ab") as windows_manual_fix:
                windows_manual_fix.write(manual_fix.encode())
        for fix_cmd_index, fix_cmd in enumerate(target_rule.fix_commands):
            replacement_dict = user_fix_input.get(fix_cmd_index, None)
            if not replacement_dict:
                if fix_cmd.replacements:
                    raise Exception(
                        f"Missing check replacement values for {fix_cmd.command}"
                    )
                parsed_command = fix_cmd.command
            else:
                parsed_command = fix_cmd.replaceCommand(replacement_dict)

            fix_script += "Write-Output '" + parsed_command + "' >> fix_script_logs.txt" + "\n"
            fix_script += "run_command " + "'" + parsed_command + " >> fix_script_logs.txt' 'Fix Script for " + vuln_id + "'" + "\n"

        with open(
                output_folder + "/" + guide_file_name + "-" + "FixScript.ps1",
                "wb") as windows_fix_script:
            windows_fix_script.write(fix_script.encode())
