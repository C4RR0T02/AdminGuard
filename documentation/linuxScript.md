# Red Hat Enterprise Linux Hardening Settings

## Fields that are available

- Rule Name (title)
- Vul ID (Group ID)
- Rule ID ()
- STIG ID ()
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

1. Display all Ruling with the following

Example: 

|Vulnerability ID|Rule ID|Serverity|Icon to See more information|Enable / Disable|
|--|--|--|--|--|
|V-230222|SV-230222r627750_rule|CAT II|More Information|Enable|

2. Check if the settings are enabled or disabled
3. Filter out the commands in the Check Text
4. Add to the baseline command list
5. Make the file downloadable

# Functions Available for Usage
|Function|Purpose|
|---|---|
|getRequiredInput(rule_list)|Get all required input from user for checking and fixing|
|createScriptFromRules(rules, user_check_input, user_fix_input, user_enable_list)|Script Generator|
|parseRulesFromXml(filename)|Parse the XML file and calculate and store all required fields|

# Class Functions `RuleInput`
|Function|Purpose|
|---|---|
|replaceUserInputOfCommand(self, command_list, user_input)||

# Class Functions `StigRule`
|Function|Purpose|
|---|---|
|calculateScore(self)|Calculate Severity Scoring and assign it back to the rule|
|getCommands(self, field)|Get all the commands before checking for Regex|


## Resources
https://www.guru99.com/manipulating-xml-with-python.html
