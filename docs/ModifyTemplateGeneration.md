# Modifying Template Generation

The modification of the Template Generation can be done by following the steps below. This document documents the various functions and classes used within the Template File Generator

## *`Classes`*

### Template Class

The Template Class takes in the variables of the template name, file content, rule dictionary and the guide type. The following is the code snippet of the `__init__` of the Template Class.

```py
def __init__(self, template_name: str, file_content: list, template_rule_dict: dict, template_type: str):
    self.template_name = template_name
    self.file_content = file_content
    self.template_rule_dict = template_rule_dict
    self.template_type = template_type
```

An example of how to create the Template Class Object is as shown below

```py
Template(filename, file_content, template_rule_dict, template_type)
```

An Example on how to use the object attributes from the Template Class

```py
# Creating Template Class Object
template = Template(filename, file_content, template_rule_dict, template_type)

# Retrieving Variables From Template Object
templateName = template.template_name
print(templateName)
fileContent = template.file_content
print(fileContent)
templateType = template.template_type
print(templateType)

# Retrieving Rule Data with Vulnerability ID
for vulnId, rule in template.template_rule_dict[0].items():
    print(rule.dictionary_fields.dictionary_fields.items())

# Retrieving Rule Data without Vulnerability ID
for index, rule in template.template_rule_dict[1].items():
    print(rule.dictionary_fields.dictionary_fields.items())
```

### RuleItems Class

The RuleItems Class takes in the variables of the vulnerability ID and the fields data dictionary. The following is the code snippet of the `__init__` of the RuleItems Class.

```py
def __init__(self, vuln_id: str, dictionary_fields: dict):
        self.vuln_id = vuln_id
        self.dictionary_fields = dictionary_fields
```

An example of how to create the RuleItems Class Object is as shown below

```py
RuleItems(vuln_id, dictionary_fields)
```

An Example on how to use the object RuleItems attributes from the Template Class

```py
# Creating Template Class Object
template = Template(filename, file_content, template_rule_dict, template_type)

# Retrieving Variables From RuleItems Object Using Template Object
# Retrieving Rule Data with Vulnerability ID
for vulnId, rule in template.template_rule_dict[0].items():
    print(rule.dictionary_fields.dictionary_fields.items())

# Retrieving Rule Data without Vulnerability ID
for index, rule in template.template_rule_dict[1].items():
    print(rule.dictionary_fields.dictionary_fields.items())
```

An Example on how to use the object attributes from the RuleItems Class

```py
# Creating RuleItems Class Object
rules = RuleItems(vuln_id, dictionary_fields)

# Retrieving Variables From RuleItems Object
vulnId = rules.vuln_id
print(vulnId)
dictionaryFields = rules.dictionary_fields
print(dictionaryFields.items())
```

## *`Functions`*

### parseTemplate(template_name: str, template_type: str)

The `parseTemplate` function is a function that takes in the filepath of the uploaded template as well as the template type of the file. This parseTemplate function parses the template file into the `nessusaudit.py` file which converts the template into a Python object. Below is an example of how the nessusaudit file is used to convert the template into a Python object

```py
audit_file = NessusAudit(template_name)
```

The objects are than sorted and organised into a list consisting of a dictionary with all vulnerabilities with VulnID and a dictionary with the index position as a key for rulings without VulnIDs. The template object is returned. Below is an example of how to use the `parseTemplate` function

```py
parseTemplate(upload_file_path, selected_template_type)
```

### genTemplate(template: Template)

The `genTemplate` function is a function that takes in the template object. This genTemplate function parses the template file and reads the content of the template file. The function makes use of a line number counter and an index counter to keep track of the line number and rule indexing.

Iterating over each line, the line content starting with the `<custom_item>` tag is found and the rule index is retrieved. The rule index is checked against the dictionary consisting of rules without the VulnID. If the index is not within the dictionary consisting of rules without the VulnID, the next few lines are read until the `reference` line is found. This line consists of the VulnID which can be used to extract the updated input stored within the dictionary to modify the file. 

Below is an example of how the function can be used

```py
genTemplate(template)
```

## *`Modification of Creation of Updated Template File`*

To modify the creation of updated template, the function, `genTemplate` is modified. Below are the steps on how to modify the function

Step 1: Locate the `genTemplate` function in the `template_gen.py` file  
Step 2: Modify the contents of the function to perform the new generation of template 
