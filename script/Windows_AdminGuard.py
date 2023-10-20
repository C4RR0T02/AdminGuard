# Imports
from urllib.parse import unquote
import os
import re
from script.AdminGuard import StigRule, Command

# Find any text between square brackets
square_bracket_regex = re.compile(r"\[[^]]+\]", re.IGNORECASE)

# Classes
class Windows(StigRule):
    def _getRequiredFields(self, field):
        command_list = []
        powershell_command_list = getPowerShellCommands()
        
        field_split = field.split("\n")
        for field_line in field_split:
            field_command = ""
            field_text_to_fill = []

            if not field_line.startswith('Enter "') or field_line.startswith("Enter '"):
                continue

            if field_line.startswith('Enter "') or field_line.startswith("Enter '"):
                if not 'Enter "q" at the' in field_line:
                    field_command = field_line.replace('Enter "', "").replace("Enter '", "").strip()
                    line_end_index = field_command.rfind('"')
                    if line_end_index != -1:
                        field_command = field_command[:line_end_index]
                        print(field_command)
                    line_end_index = field_command.rfind("'")
                    if line_end_index != -1:
                        field_command = field_command[:line_end_index]
                        print(field_command)

            for powershell_command in powershell_command_list:
                if powershell_command.startswith("# "):
                    continue
                if not field_line.startswith(powershell_command):
                    continue
                field_command = field_line.strip()
                if field_command.endswith('.'):
                    field_command = field_command[:-1]
            
            for command in square_bracket_regex.findall(field_command):
                field_text_to_fill.append(command)

            

            new_command = Command(field_command, field_text_to_fill)
            command_list.append(new_command)

        return command_list

def getPowerShellCommands():
    current_directory = os.getcwd()
    filepath = os.path.join(current_directory, 'script\powershell_commands.txt')
    with open(filepath, 'r', encoding='utf-8') as powershell_command_file:
        powershell_commands = powershell_command_file.read().splitlines()
    return powershell_commands

def windowsCreateScript(guide, user_input):

    check_script = """mkdir AdminGuard | out-null
cd AdminGuard
New-Item -Name 'check_script_logs.txt' -ItemType 'file' | out-null

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
cd AdminGuard
New-Item -Name 'fix_script_logs.txt' -ItemType 'file' | out-null

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
                
                check_script += "echo '" + parsed_command + "' >> check_script_logs.txt" + "\n"
                check_script += "run_command " + "'" + parsed_command + " >> check_script_logs.txt' 'Check Script for " + vuln_id + "'" + "\n"
            
            with open(output_folder + "/" + guide_file_name + "-" + "CheckScript.sh", "wb") as linux_check_script:
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

            fix_script += "echo '" + parsed_command + "' >> fix_script_logs.txt" + "\n"
            fix_script += "run_command " + "'" + parsed_command + " >> fix_script_logs.txt' 'Fix Script for " + vuln_id + "'" + "\n"

        with open(output_folder + "/" + guide_file_name + "-" + "FixScript.sh", "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())


# Test replacement of commands from user input
# user_input = {
#     "V-254239": {
#         "check": {
#             1: {'[account name]': 'TESTTTTTTTTT'},
#         },
#         "fix": {},    
#     },
#     "V-254243": {
#         "check": {
#             0: {'[application account name]': '1111111111111111111111'},
#             1: {'[application account name]': '2222222222222222222222'},
#           },
#         "fix": {}, 
#     },
#     "V-254244": {
#         "check": {},
#         "fix": {},    
#     },
# }


# guide = parseGuide("./script/testXmlFiles/U_MS_Windows_Server_2022_STIG_V1R3_Manual-xccdf.xml")

# createScript(guide, user_input)

# for rule in guide.stig_rule_dict:
#     print(guide.stig_rule_dict[rule].vuln_id)
#     print(guide.stig_rule_dict[rule].check_commands.__repr__())

# print(guide.stig_rule_dict["V-254239"].check_commands)
# print(guide.stig_rule_dict["V-254243"].check_commands)
# print(guide.stig_rule_dict["V-254244"].check_commands)