# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import os
import shutil
import math
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


class RuleInput:

    def __init__(self, vuln_id: str, check_replacement: str,
                 fix_replacement: str):
        self.vuln_id = vuln_id
        self.check_replacement = check_replacement
        self.fix_replacement = fix_replacement

    def __str__(self) -> str:
        return f"{str(self.vuln_id)} - {str(self.check_replacement)} - {str(self.fix_replacement)}"


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

    if guide_type == "Linux":
        starter = '<check_type:"Unix">'
    elif guide_type == "Windows":
        starter = '<check_type:"Windows" version:"2">/n<group_policy:"Microsoft Windows Server 2022">'


E = ElementMaker
IF = E("if")
CONDITION = E("condition")
CUSTOM_ITEM = E("custom_item")
THEN = E("then")
ELSE = E("else")
