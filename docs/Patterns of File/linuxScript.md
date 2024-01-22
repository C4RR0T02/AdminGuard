# Red Hat Enterprise Linux Hardening Settings

## Fields that are available

- Rule Name (title)
- Vul ID (Group ID)
- Rule ID (rule.id)
- STIG ID (version)
- Weight (rule.weight)
- Severity (rule.severity)
- Classification ()
- Group Title (title)
- Rule Title (rule.title)
- Discussion (&lt;VulnDiscussion&gt;)
- Check Text (check-content)
- Fix Text (fixtext)
- References (reference)

## Fields Tag

        - Group ID
        - Rule id
        - Rule weight
        - Rule severity
        - version
        - title
        - description
        - reference
        - fixtext


### Common patterns before the command

        $

### Common patterns a user input variable

        []
        /path/to/file
        /[path]/[to]/[file]/
        <username>

### Patterns marking the end of the command

- filter using tag and getting tag text using the .text

        </fixtext>

### Severity Category Calculation

```py

    weight = input("RULE_WEIGHT_FIELD")
    severityLevel = input("RULE_SEVERITY_FIELD")

    def severityValue(severityLevel):
        match severityLevel:
            case "no":
                severity = 1.0
            case "low":
                severity = 2.0
            case "medium":
                severity = 3.0
            case "high":
                severity = 4.0
            case "critical":
                severity = 5.0
            case _:
                severity = "Undefined"
        return severity

    def severityCategory(weight, severity):
        if severity == "Undefined":
            return severityCat = "Undefined"
        else: 
            category = (weight / 2) * severity
            match category:
                case category < 3:
                    severityCat = "Very Low"
                case category < 5:
                    severityCat = "Low"
                case category < 10:
                    severityCat = "Medium"
                case category < 13:
                    severityCat = "High"
                case category >= 17:
                    severityCat = "Very High"
                case category >= 17:
                    severityCat = "Extreme"
            return severityCat

    severity = severityValue(severityLevel)
    severityCat = severityCategory(weight, severity)

```

## Steps for Script

1. User upload script
2. Display all Ruling with the following

Example: 

|Vulnerability ID|Rule ID|Serverity|Icon to See more information|Enable / Disable|
|--|--|--|--|--|
|V-230222|SV-230222r627750_rule|CAT II|More Information|Enable|

3. Check if the settings are enabled or disabled
4. Filter out the commands in the Check Text
5. Add to the baseline command list
6. Make the file downloadable

# Functions Available for Usage
|Function|Purpose|
|---|---|
|parseGuide(filename)|Parse the Linux STIG guide and create the Guide and StigRule object|
|createScript(guide, user_input)|Create the script files for export based on user Input|

# Class Functions `Guide`
|Function|Purpose|
|---|---|
|__init__(self, guide_name, file_content, stig_rule_dict)|Create Guide objects|
|__str__(self) -> str|Easily print out formatted Guide Objects|

# Class Functions `StigRule`
|Function|Purpose|
|---|---|
|__init__(self, rule_name, rule_title, vuln_id, rule_id, rule_weight, rule_severity, stig_id, rule_fix_text, rule_description, check_content)|Create StigRule objects|
|_getRequiredFields(self, field)|Locate commands and extract out any field information where user inputs are required|
|_calculateScore(self)|Calculate severity category score|
|__str__(self) -> str|Easily print out formatted StigRules|

# Class Functions `Command`
|Function|Purpose|
|---|---|
|__init__(self, command, replacements)|Create Command objects|
|replaceCommand(self, target_replacements)|Perform replacement of fields based on the user input parsed|
|__repr__(self) -> str|Easily print out the data of the formatted Commands|

# Class Functions `RuleInput`
|Function|Purpose|
|---|---|
|__init__(self, vuln_id, check_replacement, fix_replacement)||
|__str__(self) -> str|Easily print out the formatted RuleInput|

