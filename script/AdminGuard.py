# Imports
from bs4 import BeautifulSoup
from urllib.parse import unquote
import math
import re

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

class StigRule:
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
        # @user_input: User Input of the rule

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
        self.user_input = []

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

    def getCommands(self, field):
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

    def getUserInputToFill(self, command_list):
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
    
    # def getUserInput(self, user_input_list):
    #     self.user_input = user_input_list
    
    def replaceUserInputOfCommand(self, command_list, user_input):
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

    def __str__(self) -> str:
        return f"{str(self.vuln_id)} - {str(self.rule_id)} - {str(self.rule_severity)}"

# Functions not within a class

def parseRulesFromXml(filename):
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
        
        # Calculate Category Score for each rule
        for rule in rule_list:
            rule.calculateScore()

    return rule_list



# Main
rule_list = parseRulesFromXml("./script/testXmlFiles/U_RHEL_8_STIG_V1R11_Manual-xccdf.xml")

for rule in rule_list:
    #print(rule.getUserInput(rule.getCommands(rule.check_content)))
    print(rule.replaceUserInputOfCommand(rule.getCommands(rule.check_content), rule.user_input))

# Links to external sites used

# XML MANIPULATION
# BeautifulSoup - https://www.crummy.com/software/BeautifulSoup/bs4/doc/

# REGEX
# Regex - https://docs.python.org/3/library/re.html
# Regex Generator - https://regex-generator.olafneumann.org/?sampleText=&flags=Pi
# Regex Checker - https://regex101.com/r/NYVFkU/1
