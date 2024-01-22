# Modifying Script Detection

The modification of the Script Detection can be done by following the steps below. This document documents the various functions and classes used within the STIG Script Generator Python File.

## *`Classes`*

### Guide Class

The Guide Class takes in the variables of the guide name, file content, rule dictionary and the guide type. The following is the code snippet of the `__init__` of the Guide Class.

```py
def __init__(self, guide_name: str, file_content: list,
                stig_rule_dict: dict, guide_type: str):
    self.guide_name = guide_name
    self.file_content = file_content
    self.stig_rule_dict = stig_rule_dict
    self.guide_type = guide_type
```

An example of how to create the Guide Class Object is as shown below

```py
Guide(filename, file_content, stig_rule_dict, guide_type)
```

An Example on how to use the object attributes from the Guide Class

```py
# Creating Guide Class Object
guide = Guide(guide_name, file_content,
            stig_rule_dict, guide_type)

# Retrieving Variables From Guide Object
guideName = guide.guide_name
print(guideName)
fileContent = guide.file_content
print(fileContent)
for vulnId in guide.stig_rule_dict.keys():
    print(guide.stig_rule_dict[vuln_id].items())
guideType = guide.guide_type
print(guideType)
```

### StigRule Class

The STIGRule Class takes in the fields and variables required to regenerate the STIG file as well as the rule data. The following is the code snippet of the `__init__` of the StigRule Class.

```py
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
    ...
    self.mitigation_control = mitigation_control
    self.responsibility = responsibility
    self.iacontrols = iacontrols

    # Variables Making use of Private Functions
    self.category_score = self._calculateScore()
    self.check_commands = ''
    self.fix_commands = ''
```
An example of how to create the StigRule Class Object is as shown below

```py
StigRule(rule_name, rule_title, vuln_id, rule_id, rule_weight,
        rule_severity, stig_id, rule_fix_text,
        rule_description, check_content, check_system,
        dc_title, dc_publisher, dc_type, dc_subject,
        dc_identifier, ident_system, ident_content, fix_ref,
        fix_id, check_content_ref_href, check_content_ref_name,
        false_positives, false_negatives, documentable,
        mitigations, severity_override_guidance,
        potential_impacts, third_party_tools,
        mitigation_control, responsibility, iacontrols)
```

An Example on how to use the object StigRule attributes from the Guide Class

```py
# Creating Guide Class and StigRule Class Object
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

# Getting The Commands Within the Check Content and Fix Text Fields
rule.check_commands = rule._getRequiredFields(guide_type, check_content)
rule.fix_commands = rule._getRequiredFields(guide_type, rule_fix_text)
rule_dictionary[vuln_id] = rule

guide = Guide(guide_name, file_content,
            rule_dictionary, guide_type)

# Retrieving Variables From StigRule Object Using Guide Object
for vulnId in guide.stig_rule_dict.keys():
    print(guide.stig_rule_dict[vuln_id].rule_name)
    print(guide.stig_rule_dict[vuln_id].rule_title)
    print(guide.stig_rule_dict[vuln_id].rule_id)
    print(guide.stig_rule_dict[vuln_id].rule_weight)
    print(guide.stig_rule_dict[vuln_id].rule_severity)
    print(guide.stig_rule_dict[vuln_id].stig_id)
    print(guide.stig_rule_dict[vuln_id].rule_description)
    print(guide.stig_rule_dict[vuln_id].rule_fix_text)
    print(guide.stig_rule_dict[vuln_id].fix_commands)
    print(guide.stig_rule_dict[vuln_id].check_content)
    print(guide.stig_rule_dict[vuln_id].check_commands)
    print(guide.stig_rule_dict[vuln_id].category_score)
```

An Example on how to use the object StigRule attributes

```py
# Creating Guide Class and StigRule Class Object
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

# Getting The Commands Within the Check Content and Fix Text Fields
rule.check_commands = rule._getRequiredFields(guide_type, check_content)
rule.fix_commands = rule._getRequiredFields(guide_type, rule_fix_text)

# Retrieving Variables From StigRule Objectt
ruleName = rule.rule_name
print(ruleName)
ruleTitle = rule.rule_title
print(ruleTitle)
vulnId = rule.vuln_id
print(vulnId)
ruleId = rule.rule_id
print(ruleId)
ruleWeight = rule.rule_weight
print(ruleWeight)
ruleSeverity = rule.rule_severity
print(ruleSeverity)
stigId = rule.stig_id
print(stigId)
ruleDescription = rule.rule_description
print(ruleDescription)
fixText = rule.rule_fix_text
print(fixText)
fixCommands = rule.fix_commands
print(fixCommands)
checkContent = rule.check_content
print(checkContent)
checkCommands = rule.check_commands
print(checkCommands)
categoryScore = rule.category_score
print(categoryScore)
```

#### Functions within StigRule Class

The following are the functions within the StigRule Class, functions with the `_` at the start of the function name are private functions within Python. 

##### _getRequiredFields(self, type: str, field: str)

The `_getRequiredFields` function is a private function which detects the various commands within the check content and fix text fields. 

This function takes in the type of guide as well as the field the command should be extracted from. The following is an example of how to make use of this `_getRequiredFields` private function 

```py
# Creating StigRule Object
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

# Using _getRequiredFields Function
rule.check_commands = rule._getRequiredFields(guide_type, check_content)
rule.fix_commands = rule._getRequiredFields(guide_type, rule_fix_text)
```

##### _calculateScore(self)

The `_calculateScore` function is a private function which makes use of the `rule_weight` and `rule_severity` fields. The function aims to calculate the category score by making use of the formula below

```
category_score = float(self.rule_severity) * ((self.rule_weight) / 2)
```

As the rule severity field are string values such of low, medium, high and critical, these values must first be converted. The following is the dictionary values used to convert these values.

```py
severity_Dictionary = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "no": 1,
}
```

After the calculation, the value returned to users is based of the range of score that is specified below

```py
severity_categories_dictionary = {
    "undefined": -1,
    "Very Low": 3,
    "Low": 5,
    "Medium": 10,
    "High": 13,
    "Very High": 17,
    "Extreme": float("inf"),
}
```

This function is called on the creation of the object. The following is an example of how to make use of this `_calculateScore` private function

```py
# Using _calculateScore Function From Guide Object
rule = guide.stig_rule_dict[vuln_id]
rule.category_score = rule._calculateScore()

# Using _calculateScore Function From StigRule Object
rule.category_score = rule._calculateScore()
```

## *`Functions`*

### getPowerShellCommands()

The `getPowerShellCommands` function is a function that reads the powershell_commands.txt file located within the `app/script/` folder. 

The `powershell_command.txt` consists of all valid PowerShell commands from the various modules. Reading from this text document, all commands are placed in a list and any commands commented out with a `#` will not be used to detect lines starting with that specified command. 

Example of how to comment out specific commands
```
#Get-ChildItem
# Get-ChildItem
```

### parseGuide(filename: str, guide_type: str)

The `parseGuide` function is a function that takes in the filepath of the uploaded guide as well as the guide type of the file. This parseGuide function reads from the uploaded guide and encodes the data as an XML file. 

The extraction of fields from the XML tags occur by making use of the XML encoded content and searching for the tag. Below is an example of how the content of the title within group info can be extracted

```py
# Encoding XML Data in XML Format
content = BeautifulSoup(xml_data, 'xml')

# Extracting group tag content
group_info = content.find('Group').text

# Extracting title tag from group tag content
group_info.find('title').text
```

Some content within the XML file are also stored within the XML tag as such these variables are extracted in a different manner as per shown below

```py
# Encoding XML Data in XML Format
content = BeautifulSoup(xml_data, 'xml')

# Extracting group tag content
group_info = content.find('Group').text

# Extracting rule tag content
group_rule_info = group_info.find('Rule')

# Extracting id field stored in rule tag
rule_id = group_rule_info['id']
```

Various fields within the field content may be encoded, as such the decoding of these fields are required before being able to futher extract tags. Errors may be encountered during the process of attemptng to extract tags after decoding the fields as such, the content is required to be once again parsed and encoded using the `BeautifulSoup` library. Below is an example of the use case mentioned

```py
# Encoding XML Data in XML Format
content = BeautifulSoup(xml_data, 'xml')

# Extracting group tag content
group_info = content.find('Group').text

# Extracting rule tag content
group_rule_info = group_info.find('Rule')

# Extract Rule Description
group_description_info = group_rule_info.find('description').text

# URL Decode Rule Description
group_description_info_decoded = unquote(group_description_info)

# Transform back into XML
group_description_info_xml = BeautifulSoup(
    group_description_info_decoded, 'xml')

# Extracting Encoded Tag
rule_description = group_description_info_xml.find(
    'VulnDiscussion').text

# Extracting Encoded Tags where if content does not contain info returns None
if group_description_info_xml.find('FalsePositives') is None:
    false_positives = ''
else:
    false_positives = group_description_info_xml.find(
        'FalsePositives').text
```

### linuxCreateScript(guide: Guide, enable_list: list)

The `linuxCreateScript` function is the function used for the creation of the linux scripts. The function takes in a Guide Object and a list consisting of the rules `vuln_id` that are enabled. 

The following is an example of how to use the `linuxCreateScript` function

```py
# Creating Guide Class Object
guide = Guide(guide_name, file_content, stig_rule_dict, 'Linux')

# Defining Enabled Rule List
enable_list = ['V-230309', 'V-230327', 'V-230341']

# Generating Linux Scripts
linuxCreateScript(guide, enable_list)
```

During the script generation, the following content is first added to create the folders and files required to log the process of the scripts output from application towards the machine. Below is the initial content to be appended for the files

check_script content

```py
check_script = """#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt
touch manual_check.txt

"""
```

fix_script content

```py
fix_script = """#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch fix_script_logs.txt
touch manual_fix.txt

"""
```

manual_check content

```py
manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''
```

manual_fix content

```py
manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''
```

The script will be appended to the file as the commands are looped through and contents without commands will append towards the manual check and or fix file. After the appending of the commands from each of the list of enabled ruling, the content is appended to script file. 

The file is encoded to ensure that the correct encoding is applied and the line feed is correctly used based on the operating system using the `.encode()` function in Python.

### windowsCreateScript(guide: Guide, enable_list: list)

Similarly to `linuxCreateScript` function, the `windowsCreateScript` function is the function used for the creation of the windows scripts. The function takes in a Guide Object and a list consisting of the rules `vuln_id` that are enabled.

The following is an example of how to use the `windowsCreateScript` function

```py
# Creating Guide Class Object
guide = Guide(guide_name, file_content, stig_rule_dict, 'Windows')

# Defining Enabled Rule List
enable_list = ['V-254239', 'V-254243', 'V-254244']

# Generating Linux Scripts
windowsCreateScript(guide, enable_list)
```

During the script generation, the following content is first added to create the folders and files required to log the process of the scripts output from application towards the machine. Below is the initial content to be appended for the files

check_script content

```py
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
```

fix_script content

```py
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
```

manual_check content

```py
manual_check = '''CHECK CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''
```

manual_fix content

```py
manual_fix = '''FIX CONTENT TO BE MANUALLY CHECKED
--------------------------------------------------------------
'''
```

The script will be appended to the file as the commands are looped through and contents without commands will append towards the manual check and or fix file. 

### generateXml(guide: Guide)

The `generateXml` function is a function used to generate the XML file based on the user input. This function takes in the guide object and makes use of the data stored within the guide object to generate the new XML file based of the original STIG guide. 

The following is an example of how to make use of the `generateXml` function

```py
# Creating Guide Class Object
guide = Guide(guide_name, file_content, stig_rule_dict, 'Linux')

# Generate New Guide File
generateXml(guide)
```

The generation of the XML file makes use of the `lxml` library to build the various types of elements required to generate the XML file. The previous file header is extracted to ensure these custom elements are detectable and all data stored within this elements are encoded. The file content is later decoded to append the remaining closing tags before being written into the file ready for export. 

Below is an example of how the `lxml` library was used to create the elements

```py
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

# Building the XML content with the various tags and values
etree.tostring(
    GROUP(
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
    id=rule.vuln_id), pretty_print=True).decode()
```

### generateZip(guide: Guide)

The `generateZip` function is a function used to generate the zip file based on all created files for a specific STIG guide. This function takes in the guide object and makes use of the guide name to locate the folder of all created files to zip. 

The following is an example of how to make use of the `generateZip` function

```py
# Creating Guide Class Object
guide = Guide(guide_name, file_content, stig_rule_dict, 'Linux')

# Defining Enabled Rule List
enable_list = ['V-230309', 'V-230327', 'V-230341']

# Generating Linux Scripts
linuxCreateScript(guide, enable_list)

# Generate New Guide File
generateXml(guide)

# Zip all Created Files
generateZip(guide)
```

The files, stored in `app/out-file/<guide_name>/`, will first be copied over to the `app/out-files/zip/<guide_name>/` folder and the zip file will than zip all this files before being copied back into the `app/out-file/<guide_name>/` folder.

## *`Modification of Command Detection`*

To modify the command detection, the function, `_getRequiredFields` within the `StigRule Class` is modified. Below are the steps on how to modify the function

### Linux

Step 1: Locate the `_getRequiredFields` function in the `stig_script_gen.py` file  
Step 2: Locate the `Linux` type within the first `if` statement  
Step 3: Modify the contents of the script within the for loop looping over each line of the field content

### Windows

Step 1: Locate the `_getRequiredFields` function in the `stig_script_gen.py` file  
Step 2: Locate the `Windows` type within the first `if` statement  
Step 3: Modify the contents of the script within the for loop looping over each line of the field content
