# Imports
from urllib.parse import unquote
import re
import os
from script.AdminGuard import StigRule, Command

# Find any text between square brackets
square_bracket_regex = re.compile(r"\[[^]]+\]", re.IGNORECASE)
# Find any text between slashes matching /path/to/file
path_to_file_regex = re.compile(r"\/path\/to\/file", re.IGNORECASE)
path_to_file_bracket_regex = re.compile(r"/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/\[[A-Za-z0-9]+\]/", re.IGNORECASE)
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
class Linux(StigRule):
    def _getRequiredFields(self, field):
        command_list = []
        
        field_split = field.split("\n")
        for field_line in field_split:
            field_text_to_fill = []
    
            field_line = field_line.strip()

            if not field_line.startswith("$ "):
                continue

            field_command = field_line.replace("$ ", "")

            if path_to_file_bracket_regex.findall(field_command):
                for command in path_to_file_bracket_regex.findall(field_command):
                    field_text_to_fill.append(command)
            else:
                for command in square_bracket_regex.findall(field_command):
                    if not_regex_regex.findall(command):
                        field_text_to_fill.append(command)

            for command in path_to_file_regex.findall(field_command):
                field_text_to_fill.append(command)
                
            for command in angle_bracket_regex.findall(field_command):
                field_text_to_fill.append(command)

            new_command = Command(field_command, field_text_to_fill)
            command_list.append(new_command)

        return command_list

def linuxCreateScript(guide, user_input):
    check_script = """#!/bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt

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

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split("\\")[-1]

    output_folder = os.path.join(os.getcwd(),"out-files")
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)

    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_check_input = user_input[vuln_id]["check"]
        for check_cmd_index, check_cmd in enumerate(target_rule.check_commands):
            replacement_dict = user_check_input.get(check_cmd_index, None)
            if not replacement_dict:
                if check_cmd.replacements:
                    raise Exception(f"Missing check replacement values for {check_cmd.command}")
                parsed_command = check_cmd.command
            else:
                parsed_command = check_cmd.replaceCommand(replacement_dict)
            
            check_script = check_script + "echo " + parsed_command + " >> check_script_logs.txt" + "\n"
            check_script = check_script + "run_command '" + parsed_command + " >> check_script_logs.txt' 'Check Script for " + vuln_id + "'" + "\n"
        
        with open(output_folder + "/" + guide_file_name + "-" + "CheckScript.sh", "wb") as linux_check_script:
            print(check_script)
            linux_check_script.write(check_script.encode())


    for vuln_id in user_input:
        target_rule = guide.stig_rule_dict[vuln_id]

        user_fix_input = user_input[vuln_id]["fix"]
        for fix_cmd_index, fix_cmd in enumerate(target_rule.fix_commands):
            replacement_dict = user_fix_input.get(fix_cmd_index, None)
            if not replacement_dict:
                if fix_cmd.replacements:
                    raise Exception(f"Missing check replacement values for {fix_cmd.command}")
                parsed_command = fix_cmd.command
            else:
                parsed_command = fix_cmd.replaceCommand(replacement_dict)

            fix_script += "echo " + parsed_command + " >> fix_script_logs.txt" + "\n"
            fix_script +="run_command '" +  parsed_command + " >> fix_script_logs.txt' 'Fix Script for " + vuln_id + "'" + "\n"
        with open(output_folder + "/" + guide_file_name + "-" + "FixScript.sh", "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())




# Test replacement of commands from user input
# user_input = {
#     "V-230309": {
#         "check": {
#             1: {'[PART]': 'yum', '[Test]': 'install'},
#             2: {'<file>': 'woo'},
#         },
#         "fix": {
#             1: {'[PART]': 'yum', '[Test]': 'install'},
#             2: {'<file>': 'woo'},
#         },    
#     },
#     "V-230327": {
#         "check": {},
#         "fix": {
#             0: {'<group>': 'yum', '<file>': 'install'}
#         }, 
#     },
#     "V-230222": {
#         "check": {},
#         "fix": {},    
#     },
# }

# guide = parseGuide("./script/testXmlFiles/U_RHEL_8_STIG_V1R11_Manual-xccdf.xml")

# print(createScript(guide, user_input))
# getRuleInput(guide)
