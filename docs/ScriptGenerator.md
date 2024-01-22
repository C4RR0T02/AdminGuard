# Hardening Script Generator

## :clipboard: Table Of Content

- [Hardening Script Generator](#hardening-script-generator)
  - [:clipboard: Table Of Content](#clipboard-table-of-content)
  - [Description](#description)
  - [Features and Capabilities](#features-and-capabilities)
    - [Customization of STIG rules](#customization-of-stig-rules)
    - [Generation of Files](#generation-of-files)
      - [Check Script file](#check-script-file)
      - [Fix Script file](#fix-script-file)
      - [Manual Check and Manual Fix files](#manual-check-and-manual-fix-files)
      - [Updated XML file](#updated-xml-file)
      - [ZIP file](#zip-file)
    - [Offline Access](#offline-access)
    - [Scalability](#scalability)
    - [Improve Time and Resource Efficiency](#improve-time-and-resource-efficiency)
    - [Provides Accessibility for Non-experts](#provides-accessibility-for-non-experts)
  - [Usage](#usage)
  - [Customization Notes](#customization-notes)
    - [Linux Example](#linux-example)
      - [Web Application](#web-application)
      - [Script Output](#script-output)
    - [Windows Example](#windows-example)
      - [Web Application](#web-application-1)
      - [Script Output](#script-output-1)
  - [Limitations](#limitations)
    - [1. Limited Support](#1-limited-support)
    - [2. Commands cannot be generated automatically](#2-commands-cannot-be-generated-automatically)
    - [3. Files not Cached](#3-files-not-cached)
    - [4. Files are not scanned](#4-files-are-not-scanned)
    - [5. File type is unable to be detected](#5-file-type-is-unable-to-be-detected)
  - [Possible Improvements](#possible-improvements)
    - [Caching of files](#caching-of-files)
    - [File Scanning](#file-scanning)
    - [Allow creation of custom STIG file](#allow-creation-of-custom-stig-file)
    - [File storage for previously generated files](#file-storage-for-previously-generated-files)
    - [Making use of AI to aid in creation and modification of rules](#making-use-of-ai-to-aid-in-creation-and-modification-of-rules)
    - [Modification of multiple STIG files](#modification-of-multiple-stig-files)
    - [Allowing users to modify the powershell.txt file](#allowing-users-to-modify-the-powershelltxt-file)

## Description
The hardening script generator takes in a `file` and the `type` of hardening file. Based on the type of hardening file selected, the script will be processed. A total of `SIX` files will be output - CheckScript, FixScript, Manual Check, Manual Fix, Updated XML, a zip of all files. 

The hardening file is required to be an `XML` file and the file size is to be below `50 MegaBytes`. The current guide types supported are :penguin:`Linux` and :window:`Windows`. 

## Features and Capabilities

1. [Customization of STIG rules](#Customization-of-STIG-rules)
2. [Generation of Files](Generation-of-Files)
3. [Offline Access](Offline-Access)
4. [Scalability](Scalability)
5. [Improve Time and Resource Efficiency](#improve-time-and-resource-efficiency)
6. [Provides Accessibility for Non-experts](#provides-accessibility-for-non-experts)

### Customization of STIG rules

Different Organisations may have different requirements to meet to fulfil the Data Protection Regulations applicable to the industry.

The STIG is a general guidelines provided and should be modified based on the Regulations to comply to all Data Protection Regulations applicable towards the organisation. 

With the file being generated with the content of the fields displayed to the end user, end-users are able to compare and make modification to the STIG guide based on the company regulations. 

![STIG Script Generator - Customize STIG File](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/customize_stig_file.png)

### Generation of Files

After customising the various rules, a total of `SIX` files will be output - CheckScript, FixScript, Manual Check, Manual Fix, Updated XML, a zip of all files. 

#### Check Script file

The check script file is generated from the STIG file where the rules are enabled. Based on the latest content within the file, the script generated will either be a bash script or a PowerShell script. 

This script should be applied when a user wants to check if their system is vulnerable.

![Check Script File Content](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/check_script.png)

#### Fix Script file

The fix script file is generated from the STIG file where the rules are enabled. Based on the latest content within the file, the script generated will either be a bash script or a PowerShell script. 

This script should be applied when a user wants to apply fixes towards their vulnerable system.

![Fix Script File Content](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/fix_script.png)

#### Manual Check and Manual Fix files

The manual check and fix files are files which contains the various rules which requires manual checking or fixing. The vulnerability ID, title as well as the steps to check or to manually fix.

![Manual Check File Content](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/manual_file_content.png)

#### Updated XML file

The updated XML file consists of the various rules content which may have been modified. This XML file can be uploaded into the STIG viewer and be viewed.

#### ZIP file

The zip file is a compressed file consisting of the check script, fix script, manual check , manual fix as well as the updated xml file. 

### Offline Access

This web application does not need to be connected to the internet as it does not make use of content distribution network (CDN). Instead, all files which are required are downloaded and referenced within the various pages. 

This will ensure that even without internet or within an intranet, the application is able to function without disruption. 

### Scalability

Docker containers provide a lightweight and consistent environment for applications, making it easier to manage and scale. Docker containers share the host operating system's kernel, making them more resource-efficient than traditional virtual machines. 

The docker image that is created using the docker file can be used to create docker containers. This docker image can be easily deployed into multiple docker container allowing it to easily scale up and down based on the demands of the users. 

### Improve Time and Resource Efficiency

Writing scripts manually based on STIG guidelines can be time-consuming and error-prone. A script generator simplifies this process, saving time and resources for both security professionals and system administrators.

### Provides Accessibility for Non-experts

Not all users may be experts in security configurations or scripting languages. The script generator is able to generate a script based on the guide that has been parsed. As such, by having a script generator, users are able to easily make use of the application to generate the script.

## Usage

1. Select Hardening Script Creation

![AdminGuard - Select Tool](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/select_tool.jpg)


2. Upload the STIG XML file that can be downloaded from this [link](https://public.cyber.mil/stigs/downloads/) and select the type of STIG file

![STIG Script Generator - Upload STIG File](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/upload_stig_file.png)

3. Once the file has been successfully uploaded, the rules can be customised [Customization Notes](#Customization-Notes)

![STIG Script Generator - Customize STIG File](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/customize_stig_file.png)

4. Once all rules have be reviewed, the Generate Script button, once clicked will redirect to the script download page

![STIG Script Generator - Download Files](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/download_stig_files.png)

## Customization Notes

The commands for both the Linux as well as Windows STIG guide will have to start with the syntax for the commands to be generated within the script. The syntax are as follows.

Linux: 
```
$<space character>
```

Windows:
```
Enter "
Enter '
Powershell Commands
```

See Examples Below:
1. [Linux Example](#linux-example)
2. [Windows Example](#windows-example)

### Linux Example

#### Web Application 

<strong>Vulnerability ID:</strong> V-230341  <strong>Rule ID:</strong> SV-230341r743978_rule  <strong>Severity:</strong> High  <strong>Enable:</strong> [X]

Title:

```
RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur.
```
Vulnerability Description:

```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.

Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128
```
Vulnerability Fix:

```
Configure the operating system to prevent informative messages from being presented at logon attempts.

Add/Modify the "/etc/security/faillock.conf" file to match the following line:

silent
```
Vulnerability Check:

```
Note: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the "/etc/security/faillock.conf" file is configured to prevent informative messages from being presented at logon attempts:

$ sudo grep silent /etc/security/faillock.conf

silent

If the "silent" option is not set, is missing or commented out, this is a finding.
```

#### Script Output

Commands Retrieved from Fix Script:

```

```

Commands Retrieved from Check Script:

```
sudo grep silent /etc/security/faillock.conf
```

### Windows Example 

#### Web Application 

<strong>Vulnerability ID:</strong> V-254244  <strong>Rule ID:</strong> SV-254244r848548_rule  <strong>Severity:</strong> High  <strong>Enable:</strong> [X]

Title:

```
Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.
```
Vulnerability Description:

```
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

Windows LAPS must be used to change the built-in Administrator account password.
```
Vulnerability Fix:

```
Change the built-in Administrator account password at least every "60" days.

Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. 
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747  
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status
```
Vulnerability Check:

```
Review the password last set date for the built-in Administrator account.

Domain controllers:

Open "PowerShell".

Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

Member servers and standalone or nondomain-joined systems:

Open "Command Prompt".

Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

(The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

If the "PasswordLastSet" date is greater than "60" days old, this is a finding.
```

#### Script Output

Commands Retrieved from Fix Script:

```

```

Commands Retrieved from Check Script:

```
Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet
Net User [account name] | Find /i "Password Last Set"
```

## Limitations

1. [Limited Support](#limited-support)
2. [Commands cannot be generated automatically](#commands-cannot-be-generated-automatically)
3. [Files are not cached](#files-not-cached)
4. [Files are not scanned](#4-files-are-not-scanned)
5. [File type is unable to be detected](#5-file-type-is-unable-to-be-detected)

### 1. Limited Support

The current script does not support all guides and only support Windows and Linux OS hardening. While the script can be edited, to follow and make use of either a Windows or Linux OS script syntax, the script will have to be edited further before applying it to the system.

The detection of Windows commands furthermore makes use of PowerShell Commands, as such if a new PowerShell command is being added to the various PowerShell modules, the command will also need to be updated within the `powershell_command.txt` file.

### 2. Commands cannot be generated automatically

While the commands within the Linux can generally be identified and extracted, there are outlier cases as the guides are written by multiple authors, as such some commands may be left out and not be placed within the script. 

Furthermore, some guides like the Windows STIG guide is mainly written in plain English as well as steps to indicate how to check or fix the system using the Graphical User Interface (GUI), While there may be Command Line Interface (CLI) commands that are able to execute and perform the hardening, the script is unable to convert this command for the end-users. 

However, this limitations can be tackled by [making use of AI to aid in the creation as well as modification of the rules](#making-use-of-ai-to-aid-in-creation-and-modification-of-rules).

### 3. Files not Cached

While the user is able to upload the file and the file is passed between each page, if the server is restarted, the files though stored within the system will cause an error due to the dictionary not storing the data of all files previously uploaded within the system. 

When the same file is uploaded within the system, the data is also reprocessed making the users wait while the content of the file may be the same as the previous file uploaded. 

This limitation can be tackled by implementing a [caching for files](#caching-of-files).

### 4. Files are not scanned

While the file type along with the size of the file uploaded by the users are checked, the file content are not checked for any malicious intent. As such if a user is to upload a file that is able to bypass the xml checks and below the set file size, the file will be executed within the system to perform the script which will be detrimental. 

While the effects are not really seen when deploying on a docker container, if the application is installed locally on a system to be deployed, Confidentiality, Integrity, and Availability will be impacted.

Confidentiality:

```
Attackers will get unauthorised access to any sensitive information generated
```

Integrity:

```
Attackers may upload malicious scripts or code that could alter or manipulate data within the system. 
```

Availability:

```
Attackers might upload a file containing a denial-of-service (DoS) attack that consumes system resources, leading to service disruptions
```

### 5. File type is unable to be detected

The file type indicates the system the script is applicable on. The current supported file types are `Windows` and `Linux`. While these are the only Operating Systems currently supported, when there are many more Operating Systems or System product support, having the users select a guide type from a list will not be the best option. While the type of operating system is indicated within the file, due to the various naming the file has, more time is still needed to analyse the file names for those making use of the Linux Operating System. 

Example Filenames of other Linux Operating Systems

```
Canonical Ubuntu 18.04 LTS STIG - Ver 2, Rel 12
Canonical Ubuntu 20.04 LTS STIG - Ver 1, Rel 10
Canonical Ubuntu 20.04 LTS STIG for Ansible - Ver 1, Rel 10
Oracle Linux 7 STIG - Ver 2, Rel 13
Oracle Linux 8 STIG - Ver 1, Rel 8
Red Hat Enterprise Linux 7 STIG - Ver 3, Rel 13
Red Hat Enterprise Linux 8 STIG - Ver 1, Rel 12
Red Hat Enterprise Linux 9 STIG - Ver 1, Rel 1
SUSE Linux Enterprise Server 12 STIG - Ver 2, Rel 12
SUSE Linux Enterprise Server 15 STIG - Ver 1, Rel 11
```

## Possible Improvements

1. [Caching of files](#caching-of-files)
2. [File Scanning](#file-scanning)
3. [Allow creation of custom STIG file](#allow-creation-of-custom-stig-file)
4. [File storage for previously generated files](#file-storage-for-previously-generated-files)
5. [Making use of AI to aid in creation and modification of rules](#making-use-of-ai-to-aid-in-creation-and-modification-of-rules)
6. [Modification of multiple STIG files](#modification-of-multiple-stig-files)
7. [Allowing users to modify the powershell.txt file](#allowing-users-to-modify-the-powershelltxt-file)

### Caching of files

The caching of files will enable users to quickly load file with the same content on the server faster. It will also help to load the data of the files into the dictionary after the server restarts. This will ensure that the files will be able to be quickly used by the end users and not have to wait and upload the file again.

### File Scanning

Making use of not just a extension checker as well as a file size checker, other information of the files uploaded should also be checked. These could possibly be an antivirus scan making use of antiviruses similar to VirusTotal APIs to check and scan the file to ensure the file is not malicious or holds malicious code. 

By scanning the uploaded files, the chances of malicious files and code executions are significantly reduced. 

### Allow creation of custom STIG file

With the functionality that the users is now able to edit the various fields within the document, the addition of STIG rules and creation of the custom STIG file will provide the organisation with more flexibility. 

With the allowance of adding more rules, the end user can better customise the STIG file to better suit the regulations implied. Being able to add or remove unused rules in the STIG file. 

On top of being able to add new rules, the general guide information can also be customised to better describe the STIG file created by the end-user.

### File storage for previously generated files

Foreseeing there will be many files that are generated by users concurrently, a proper file storage can be set up recording the guide information as well as the creation time to be able to plot it within a table which will allow users to download past scripts created by the users. 

### Making use of AI to aid in creation and modification of rules

Making use of AI, rules can be more accurately picked up to generate on the script and will not need to rely on any of the starting prefix or the powershell.txt document to ensure that it is a valid command. Making use of a large language model over generative AI model will help the AI to better pick up and make decisions to decide if it is a command. 

### Modification of multiple STIG files 

Instead of requiring users to restart the process and edit multiple files one at a time, the application can be modified to allow users to upload multiple STIG files and various pages to allow the users to quickly modify the rules at once before being able to generate all the various scripts categorised by the name of the guides and zipped into one folder for the users to easily audit and modify the files. 

### Allowing users to modify the powershell.txt file

As the PowerShell script is required to be updated whenever the module is updated, a user interface should be added for users to update the file to the latest or to add the PowerShell module commands in. This will ensure that only commands that the user would want to pick up as well as new commands will be detected, picked up and recognised as a command when the script is being generated. 
