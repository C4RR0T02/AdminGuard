# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import math
import os
import shutil
import zipfile
from lxml.builder import ElementMaker
from lxml import etree

root_dir = os.getcwd()


class Guide:

    def __init__(self, guide_name: str, file_content: list,
                 stig_rule_dict: dict, guide_type: str):
        self.guide_name = guide_name
        self.file_content = file_content
        self.stig_rule_dict = stig_rule_dict
        self.guide_type = guide_type

    def __str__(self) -> str:
        return f"{str(self.guide_name)} - {str(self.file_content)} - {str(self.stig_rule_dict)}"


class StigRule:

    def __init__(self, rule_name: str, rule_title: str, vuln_id: str,
                 rule_id: str, rule_weight: str, rule_severity: str,
                 stig_id: str, rule_fix_text: str, rule_description: str,
                 check_content: str, check_system: str, dc_title: str,
                 dc_publisher: str, dc_type: str, dc_subject: str,
                 dc_identifier: str, ident_system: str, ident_content: str,
                 fix_ref: str, fix_id: str, check_content_ref_href: str,
                 check_content_ref_name: str, false_positives: str,
                 false_negatives: str, documentable: str, mitigations: str,
                 severity_override_guidance: str, potential_impacts: str,
                 third_party_tools: str, mitigation_control: str,
                 responsibility: str, iacontrols: str):
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
        self.check_system = check_system
        self.dc_title = dc_title
        self.dc_publisher = dc_publisher
        self.dc_type = dc_type
        self.dc_subject = dc_subject
        self.dc_identifier = dc_identifier
        self.ident_system = ident_system
        self.ident_content = ident_content
        self.fix_ref = fix_ref
        self.fix_id = fix_id
        self.check_content_ref_href = check_content_ref_href
        self.check_content_ref_name = check_content_ref_name
        self.false_positives = false_positives
        self.false_negatives = false_negatives
        self.documentable = documentable
        self.mitigations = mitigations
        self.severity_override_guidance = severity_override_guidance
        self.potential_impacts = potential_impacts
        self.third_party_tools = third_party_tools
        self.mitigation_control = mitigation_control
        self.responsibility = responsibility
        self.iacontrols = iacontrols

        self.category_score = self._calculateScore()
        self.check_commands = ''
        self.fix_commands = ''

    def _getRequiredFields(self, type: str, field: str):
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

    def replaceFields(self, field: str, replacement: str):
        field_data = self.field
        if field_data is None:
            self.field = field_data
        else:
            self.field = replacement

    def __str__(self) -> str:
        return f"{str(self.rule_name)} - {str(self.rule_title)} - {str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_weight)} - {str(self.rule_severity)} - {str(self.stig_id)} - {str(self.rule_fix_text)} - {str(self.rule_description)} - {str(self.check_content)} - {str(self.category_score)}"


def getPowerShellCommands():
    filepath = os.path.join(root_dir, 'app', 'script',
                            'powershell_commands.txt')
    with open(filepath, 'r', encoding='utf-8') as powershell_command_file:
        powershell_commands = powershell_command_file.read().splitlines()
    return powershell_commands


def parseGuide(filename: str, guide_type: str):
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

        # Extract Reference Information from Rule Information
        reference_info = group_rule_info.find('reference')
        dc_title = reference_info.find('dc:title').text
        dc_publisher = reference_info.find('dc:publisher').text
        dc_type = reference_info.find('dc:type').text
        dc_subject = reference_info.find('dc:subject').text
        dc_identifier = reference_info.find('dc:identifier').text

        # Extract Ident Information from Rule Information
        ident_system = group_rule_info.find('ident')['system']
        ident_content = group_rule_info.find('ident').text

        # Extract Fix Information from Rule Information
        fix_ref = group_rule_info.find('fixtext')['fixref']
        rule_fix_text = group_rule_info.find('fixtext').text
        fix_id = group_rule_info.find('fix')['id']

        # Extract Rule Description
        group_description_info = group_rule_info.find('description').text
        # URL Decode Rule Description
        group_description_info_decoded = unquote(group_description_info)
        # Transform back into XML
        group_description_info_xml = BeautifulSoup(
            group_description_info_decoded, 'xml')
        rule_description = group_description_info_xml.find(
            'VulnDiscussion').text
        # Check if these values are present in the XML
        if group_description_info_xml.find('FalsePositives') is None:
            false_positives = ''
        else:
            false_positives = group_description_info_xml.find(
                'FalsePositives').text
        if group_description_info_xml.find('FalseNegatives') is None:
            false_negatives = ''
        else:
            false_negatives = group_description_info_xml.find(
                'FalseNegatives').text
        if group_description_info_xml.find('Documentable') is None:
            documentable = ''
        else:
            documentable = group_description_info_xml.find('Documentable').text
        if group_description_info_xml.find('Mitigations') is None:
            mitigations = ''
        else:
            mitigations = group_description_info_xml.find('Mitigations').text
        if group_description_info_xml.find('SeverityOverrideGuidance') is None:
            severity_override_guidance = ''
        else:
            severity_override_guidance = group_description_info_xml.find(
                'SeverityOverrideGuidance').text
        if group_description_info_xml.find('PotentialImpacts') is None:
            potential_impacts = ''
        else:
            potential_impacts = group_description_info_xml.find(
                'PotentialImpacts').text
        if group_description_info_xml.find('ThirdPartyTools') is None:
            third_party_tools = ''
        else:
            third_party_tools = group_description_info_xml.find(
                'ThirdPartyTools').text
        if group_description_info_xml.find('MitigationControl') is None:
            mitigation_control = ''
        else:
            mitigation_control = group_description_info_xml.find(
                'MitigationControl').text
        if group_description_info_xml.find('Responsibility') is None:
            responsibility = ''
        else:
            responsibility = group_description_info_xml.find(
                'Responsibility').text
        if group_description_info_xml.find('IAControls') is None:
            iacontrols = ''
        else:
            iacontrols = group_description_info_xml.find('IAControls').text

        # Extract Check Information from Rule Information
        check_rule_info = group_rule_info.find('check')
        check_system = check_rule_info['system']
        check_content_ref_href = check_rule_info.find(
            'check-content-ref')['href']
        check_content_ref_name = check_rule_info.find(
            'check-content-ref')['name']
        check_content = check_rule_info.find('check-content').text

        # Create Object
        rule = StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight,
                        rule_severity, stig_id, rule_fix_text,
                        rule_description, check_content, check_system,
                        dc_title, dc_publisher, dc_type, dc_subject,
                        dc_identifier, ident_system, ident_content, fix_ref,
                        fix_id, check_content_ref_href, check_content_ref_name,
                        false_positives, false_negatives, documentable,
                        mitigations, severity_override_guidance,
                        potential_impacts, third_party_tools,
                        mitigation_control, responsibility, iacontrols)
        rule.check_commands = rule._getRequiredFields(guide_type,
                                                      check_content)
        rule.fix_commands = rule._getRequiredFields(guide_type, rule_fix_text)
        rule_dictionary[vuln_id] = rule

    # Create Guide Object
    guide = Guide(filename, group_id_tags, rule_dictionary, guide_type)

    return guide


def linuxCreateScript(guide: Guide, enable_list: list):

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]

    output_folder = os.path.join(root_dir, "app", "out-files")

    # Remove existing files if they exist or create folders if they don't exist
    if os.path.isdir(output_folder) and os.path.isdir(
            os.path.join(output_folder, guide_file_name)):
        subdirectory = os.path.join(output_folder, guide_file_name)
        for file in os.listdir(subdirectory):
            os.remove(os.path.join(subdirectory, file))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if not os.path.isdir(os.path.join(output_folder, guide_file_name)):
        os.chdir(output_folder)
        os.mkdir(guide_file_name)
        os.chdir(root_dir)

    # Create check and fix scripts, and manual check and fix files
    check_script = """#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt
touch manual_check.txt
cd ..

"""

    fix_script = """#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch fix_script_logs.txt
touch manual_fix.txt
cd ..

"""

    manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    # Write manual check and fix files
    with open(
            output_folder + "/" + guide_file_name + "/" + guide_file_name +
            "-" + "ManualCheck.txt", "ab") as linux_manual_check:
        linux_manual_check.write(manual_check.encode())

    with open(
            output_folder + "/" + guide_file_name + "/" + guide_file_name +
            "-" + "ManualFix.txt", "ab") as linux_manual_fix:
        linux_manual_fix.write(manual_fix.encode())

    # if no rules are enabled, write check and fix scripts
    if len(enable_list) == 0:
        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "CheckScript.sh", "wb") as linux_check_script:
            linux_check_script.write(check_script.encode())
        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "FixScript.sh", "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())

    # if rules are enabled, write check and fix scripts with commands
    for vuln_id in enable_list:
        target_rule = guide.stig_rule_dict[vuln_id]
        # if no commands are in the list, indicate that it requires manual check
        if len(target_rule.check_commands) == 0:
            check_script += "echo 'Manual check required for " + vuln_id + "' >> check_script_logs.txt" + "\n"
            manual_check = vuln_id + " - " + target_rule.rule_title + "\n" + target_rule.check_content + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "/" +
                    guide_file_name + "-" + "ManualCheck.txt",
                    "ab") as linux_manual_check:
                linux_manual_check.write(manual_check.encode())

        # if commands are in the list, write them to the check script
        for check_cmd in target_rule.check_commands:
            check_script += "echo '" + check_cmd + "' >> check_script_logs.txt" + "\n"
            check_script += check_cmd + " >> check_script_logs.txt || echo " + '"Error while running Check Script for ' + vuln_id + '" >> error_logs.txt' + "\n"

        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "CheckScript.sh", "wb") as linux_check_script:
            linux_check_script.write(check_script.encode())

    for vuln_id in enable_list:
        target_rule = guide.stig_rule_dict[vuln_id]

        # if no commands are in the list, indicate that it requires manual fix
        if len(target_rule.fix_commands) == 0:
            fix_script += "echo 'Manual fix required for " + vuln_id + "' >> fix_script_logs.txt" + "\n"
            manual_fix = vuln_id + " - " + target_rule.rule_title + "\n" + target_rule.rule_fix_text + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "/" +
                    guide_file_name + "-" + "ManualFix.txt",
                    "ab") as linux_manual_fix:
                linux_manual_fix.write(manual_fix.encode())

        # if commands are in the list, write them to the fix script
        for fix_cmd in target_rule.fix_commands:
            fix_script += "echo '" + fix_cmd + "' >> fix_script_logs.txt" + "\n"
            fix_script += fix_cmd + " >> fix_script_logs.txt || echo " + '"Error while running Fix Script for ' + vuln_id + '" >> error_logs.txt' + "\n"

        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "FixScript.sh", "wb") as linux_fix_script:
            linux_fix_script.write(fix_script.encode())


def windowsCreateScript(guide: Guide, enable_list: list):

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]

    output_folder = os.path.join(root_dir, "app", "out-files")

    # Remove existing files if they exist or create folders if they don't exist
    if os.path.isdir(output_folder) and os.path.isdir(
            os.path.join(output_folder, guide_file_name)):
        subdirectory = os.path.join(output_folder, guide_file_name)
        for file in os.listdir(subdirectory):
            os.remove(os.path.join(subdirectory, file))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if not os.path.isdir(os.path.join(output_folder, guide_file_name)):
        os.chdir(output_folder)
        os.mkdir(guide_file_name)
        os.chdir(root_dir)

    # Create check and fix scripts, and manual check and fix files
    check_script = """mkdir AdminGuard | out-null
Set-Location AdminGuard
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
Set-Location AdminGuard
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

    manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''

    # Write manual check and fix files
    with open(
            output_folder + "/" + guide_file_name + "/" + guide_file_name +
            "-" + "ManualCheck.txt", "ab") as windows_manual_check:
        windows_manual_check.write(manual_check.encode())

    with open(
            output_folder + "/" + guide_file_name + "/" + guide_file_name +
            "-" + "ManualFix.txt", "ab") as windows_manual_fix:
        windows_manual_fix.write(manual_fix.encode())

    # if no rules are enabled, write check and fix scripts
    if len(enable_list) == 0:
        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "CheckScript.ps1", "wb") as windows_check_script:
            windows_check_script.write(check_script.encode())
        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "FixScript.ps1", "wb") as windows_fix_script:
            windows_fix_script.write(fix_script.encode())

    for vuln_id in enable_list:
        target_rule = guide.stig_rule_dict[vuln_id]

        # if no commands are in the list, indicate that it requires manual check
        if len(target_rule.check_commands) == 0:
            check_script += "Write-Output 'Manual check required for " + vuln_id + "' >> check_script_logs.txt" + "\n"
            manual_check = vuln_id + " - " + target_rule.rule_title + "\n" + target_rule.check_content + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "/" +
                    guide_file_name + "-" + "ManualCheck.txt",
                    "ab") as windows_manual_check:
                windows_manual_check.write(manual_check.encode())

        # if commands are in the list, write them to the check script
        for check_cmd in target_rule.check_commands:
            check_script += "Write-Output '" + check_cmd + "' >> check_script_logs.txt" + "\n"
            check_script += "run_command " + "'" + check_cmd + " >> check_script_logs.txt' 'Check Script for " + vuln_id + "'" + "\n"

        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "CheckScript.ps1", "wb") as windows_check_script:
            windows_check_script.write(check_script.encode())

    for vuln_id in enable_list:
        target_rule = guide.stig_rule_dict[vuln_id]

        # if no commands are in the list, indicate that it requires manual fix
        if len(target_rule.fix_commands) == 0:
            fix_script += "Write-Output 'Manual fix required for " + vuln_id + "' >> fix_script_logs.txt" + "\n"
            manual_fix = vuln_id + " - " + target_rule.rule_title + "\n" + target_rule.rule_fix_text + "\n" + "--------------------------------------------------------------" + "\n"
            with open(
                    output_folder + "/" + guide_file_name + "/" +
                    guide_file_name + "-" + "ManualFix.txt",
                    "ab") as windows_manual_fix:
                windows_manual_fix.write(manual_fix.encode())

        # if commands are in the list, write them to the fix script
        for fix_cmd in target_rule.fix_commands:
            fix_script += "Write-Output '" + fix_cmd + "' >> fix_script_logs.txt" + "\n"
            fix_script += "run_command " + "'" + fix_cmd + " >> fix_script_logs.txt' 'Fix Script for " + vuln_id + "'" + "\n"

        with open(
                output_folder + "/" + guide_file_name + "/" + guide_file_name +
                "-" + "FixScript.ps1", "wb") as windows_fix_script:
            windows_fix_script.write(fix_script.encode())


def generateXml(guide: Guide):
    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]
    file = os.path.join(root_dir, "app", "uploads", "stig",
                        guide_file_name + ".xml")
    output_folder = os.path.join(root_dir, "app", "out-files")
    file_content = ''
    line_number = 0

    # Remove existing files if they exist or create folders if they don't exist
    if os.path.isdir(output_folder) and os.path.isdir(
            os.path.join(output_folder, guide_file_name)):
        subdirectory = os.path.join(output_folder, guide_file_name)
        if file in os.listdir(subdirectory):
            os.remove(os.path.join(subdirectory, file))
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if not os.path.isdir(os.path.join(output_folder, guide_file_name)):
        os.chdir(output_folder)
        os.mkdir(guide_file_name)
        os.chdir(root_dir)

    # Read first 20 lines of the file and append it to the new file content
    with open(file, 'r', encoding='utf-8') as guide_file:
        guide_data = guide_file.readlines()
        while line_number < 21:
            file_content += guide_data[line_number]
            line_number += 1

    # Creating the XML elements
    E = ElementMaker()
    EMAPPEDDC = ElementMaker(namespace='http://purl.org/dc/elements/1.1/',
                             nsmap={'dc': 'http://purl.org/dc/elements/1.1/'})
    GROUP = E.Group
    TITLE = E.title
    DESCRIPTION = E.description
    RULE = E.Rule
    VERSION = E.version
    REFERENCE = E.reference
    DC_TITLE = EMAPPEDDC.title
    DC_PUBLISHER = EMAPPEDDC.publisher
    DC_TYPE = EMAPPEDDC.type
    DC_SUBJECT = EMAPPEDDC.subject
    DC_IDENTIFIER = EMAPPEDDC.identifier
    IDENT = E.ident
    FIXTEXT = E.fixtext
    FIX = E.fix
    CHECK = E.check

    for rule in guide.stig_rule_dict.values():

        # Encode the description of the rule to prevent XML errors appending any information that is missing
        encoded_description = '&lt;VulnDiscussion&gt;' + rule.rule_description + '&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;' + rule.false_positives + '&lt;/FalsePositives&gt;&lt;FalseNegatives&gt;' + rule.false_negatives + '&lt;/FalseNegatives&gt;&lt;Documentable&gt;' + rule.documentable + '&lt;/Documentable&gt;&lt;Mitigations&gt;' + rule.mitigations + '&lt;/Mitigations&gt;&lt;SeverityOverrideGuidance&gt;' + rule.severity_override_guidance + '&lt;/SeverityOverrideGuidance&gt;&lt;PotentialImpacts&gt;' + rule.potential_impacts + '&lt;/PotentialImpacts&gt;&lt;ThirdPartyTools&gt;' + rule.third_party_tools + '&lt;/ThirdPartyTools&gt;&lt;MitigationControl&gt;' + rule.mitigation_control + '&lt;/MitigationControl&gt;&lt;Responsibility&gt;' + rule.responsibility + '&lt;/Responsibility&gt;&lt;IAControls&gt;' + rule.iacontrols + '&lt;/IAControls&gt;'

        # Append the rule to the file content and display it in a neat and readable format
        file_content += etree.tostring(GROUP(
            TITLE(rule.rule_title, ),
            DESCRIPTION('&lt;GroupDescription&gt;&lt;/GroupDescription&gt;', ),
            RULE(
                VERSION(rule.stig_id, ),
                TITLE(rule.rule_title, ),
                DESCRIPTION(encoded_description, ),
                REFERENCE(
                    DC_TITLE(rule.dc_title, ),
                    DC_PUBLISHER(rule.dc_publisher, ),
                    DC_TYPE(rule.dc_type, ),
                    DC_SUBJECT(rule.dc_subject, ),
                    DC_IDENTIFIER(rule.dc_identifier, ),
                ),
                IDENT(
                    rule.ident_content,
                    system=rule.ident_system,
                ),
                FIXTEXT(
                    rule.rule_fix_text,
                    fixref=rule.fix_ref,
                ),
                FIX(id=rule.fix_id, ),
                CHECK(E("check-content-ref",
                        href=rule.check_content_ref_href,
                        name=rule.check_content_ref_name),
                      E("check-content", rule.check_content),
                      system=rule.check_system),
                id=rule.rule_id,
                weight=rule.rule_weight,
                severity=rule.rule_severity,
            ),
            id=rule.vuln_id),
                                       pretty_print=True).decode()

    # Append the closing tag for the XML file
    file_content += '</Benchmark>' + "\n"

    # Write the file content to the output folder
    with open(
            os.path.join(output_folder, guide_file_name,
                         "updated-" + guide_file_name + ".xml"),
            "wb") as windows_fix_script:
        windows_fix_script.write(file_content.encode())


def generateZip(guide: Guide):

    guide_file_name = guide.guide_name.split("/")[-1].split(".")[0].split(
        "\\")[-1]
    output_folder = os.path.join(root_dir, "app", "out-files", guide_file_name)
    zipping_directory = os.path.join(root_dir, "app", "out-files", "zip",
                                     guide_file_name)
    zipped_file = os.path.join(output_folder, guide_file_name + ".zip")
    temp_zipped_file = os.path.join(zipping_directory,
                                    guide_file_name + ".zip")

    # Remove existing file if they exist or create folders if they don't exist
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)
    if os.path.isfile(zipped_file):
        os.remove(zipped_file)
    if not os.path.isdir(zipping_directory):
        os.makedirs(zipping_directory)

    os.chdir(zipping_directory)

    with zipfile.ZipFile(temp_zipped_file,
                         "w",
                         compression=zipfile.ZIP_DEFLATED,
                         compresslevel=5) as zipf:
        for file in os.listdir(output_folder):
            # Skip zipped files
            if file.endswith(".zip"):
                continue
            file_path = os.path.join(output_folder, file)
            # Copy file to zipping directory
            shutil.copyfile(file_path, os.path.join(zipping_directory, file))
            # Add file to zip archive
            zipf.write(file)
    # Copy zipped file to output folder
    shutil.copyfile(temp_zipped_file, zipped_file)

    os.chdir(root_dir)
