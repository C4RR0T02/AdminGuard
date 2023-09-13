# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote

# Classes

class StigRule:
    def __init__(self, rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_description, check_content):
        self.rule_name = rule_name
        self.rule_title = rule_title
        self.vuln_id = vuln_id
        self.rule_id = rule_id
        self.rule_weight = rule_weight
        self.rule_severity = rule_severity
        self.stig_id = stig_id
        self.rule_description = rule_description
        self.check_content = check_content

    

# Defining Variables

group_id_list = []

# Functions

def initialize():
    group_id_list = []
    return group_id_list

def createObject(filename):
    # Initialize Variables
    initialize()
    # Open XML File
    with open(filename, 'r', encoding='utf-8') as xml_file:
        xml_data = xml_file.read()
        content = BeautifulSoup(xml_data, 'xml')

        # Find all Group tags with the id attribute
        group_id_tags = content.find_all('Group', id=True)
        for group_id_tag in group_id_tags:
            group_id = group_id_tag['id']
            group_id_list.append(group_id)

        # Populate StigRule Object
        for group_id in group_id_list:
            # Find correct Group Information to create an object
            if group_id == content.find('Group')['id']:
                
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
                StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_description, check_content)

# def 



# Main
createObject("./script/testXmlFiles/U_RHEL_8_STIG_V1R11_Manual-xccdf.xml")

