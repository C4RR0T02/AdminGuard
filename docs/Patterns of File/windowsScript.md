# Windows Server 2022 Hardening Settings

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

        Open "
        Enter "
        *Defender* // Default to use Defender



### Common patterns a user input variable

        [account name]
        [application account name]
        c:\temp\file.xml
        followed by the directory

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

### Split English from CLI Command

```py
array = ['Enter "Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet", where [application account name] is the name of the manually managed application/service account.',"Enter 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet', where [application account name] is the name of the manually managed application/service account."]


for field_line in array:
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

```

## Output File

```ps1
append "| Out-File [file/path]"
```

## Steps for Script

1. User upload script and commands of powershell on their device
   
        get-help * | Select-object Name

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
|||
|||

# Class Functions `Guide`
|Function|Purpose|
|---|---|
|||
|||

# Class Functions `StigRule`
|Function|Purpose|
|---|---|
|||
|||
|||
|||

# Class Functions `Command`
|Function|Purpose|
|---|---|
|||
|||
|||

# Class Functions `RuleInput`
|Function|Purpose|
|---|---|
|||
|||
