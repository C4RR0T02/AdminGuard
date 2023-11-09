import os
from ..app import *


# def test_get_required_field_linux_check_1():
#     stig_rule = StigRule(
#         "", "", "", "", None, '', '',
#         '''Set the mode on files being executed by the local initialization files with the following command:
#         $ sudo chmod test
#         $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]
#         $ sudo chmod 0755 <file>
#         $ sudo ssh-keygen -y -f /path/to/file
#         $ sudo rm /[path]/[to]/[file]/.shosts''', '',
#         '''Verify that local initialization files do not execute world-writable programs.

#         Check the system for world-writable files.

#         The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
#         $ sudo chmod test
#         $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]

#         For all files listed, check for their presence in the local initialization files with the following commands:

#         Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

#         $ sudo grep <file> /home/*/.*
#         $ sudo ssh-keygen -y -f /path/to/file
#         $ sudo rm /[path]/[to]/[file]/.shosts

#         If any local initialization files are found to reference world-writable files, this is a finding.''',
#         '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
#     )

#     assert str(
#         stig_rule._getRequiredFields("Linux", stig_rule.check_content)
#     ) == '''[Command(sudo chmod test - []), Command(sudo find [PART] -xdev -type f -perm -0002 -print [Test] - ['[PART]', '[Test]']), Command(sudo grep <file> /home/*/.* - ['<file>']), Command(sudo ssh-keygen -y -f /path/to/file - ['/path/to/file']), Command(sudo rm /[path]/[to]/[file]/.shosts - ['/[path]/[to]/[file]/'])]'''


# def test_get_required_field_linux_check_2():
#     stig_rule = StigRule(
#         "", "", "", "", None, '', '',
#         'Set the mode on files being executed by the local initialization files with the following command:',
#         '',
#         '''Verify that local initialization files do not execute world-writable programs.

#         Check the system for world-writable files.

#         The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
        
#         For all files listed, check for their presence in the local initialization files with the following commands:

#         Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

#         If any local initialization files are found to reference world-writable files, this is a finding.''',
#         '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
#     )

#     assert str(stig_rule._getRequiredFields("Linux",
#                                             stig_rule.check_content)) == '[]'


# def test_get_required_field_linux_fix_1():
#     stig_rule = StigRule(
#         "", "", "", "", None, '', '',
#         '''Set the mode on files being executed by the local initialization files with the following command:
#         $ sudo chmod test
#         $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]
#         $ sudo chmod 0755 <file>
#         $ sudo ssh-keygen -y -f /path/to/file
#         $ sudo rm /[path]/[to]/[file]/.shosts''', '',
#         '''Verify that local initialization files do not execute world-writable programs.

#         Check the system for world-writable files.

#         The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
#         $ sudo chmod test
#         $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]

#         For all files listed, check for their presence in the local initialization files with the following commands:

#         Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

#         $ sudo grep <file> /home/*/.*
#         $ sudo ssh-keygen -y -f /path/to/file
#         $ sudo rm /[path]/[to]/[file]/.shosts

#         If any local initialization files are found to reference world-writable files, this is a finding.''',
#         '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
#     )

#     assert str(
#         stig_rule._getRequiredFields("Linux", stig_rule.rule_fix_text)
#     ) == '''[Command(sudo chmod test - []), Command(sudo find [PART] -xdev -type f -perm -0002 -print [Test] - ['[PART]', '[Test]']), Command(sudo chmod 0755 <file> - ['<file>']), Command(sudo ssh-keygen -y -f /path/to/file - ['/path/to/file']), Command(sudo rm /[path]/[to]/[file]/.shosts - ['/[path]/[to]/[file]/'])]'''


# def test_get_required_field_linux_fix_2():
#     stig_rule = StigRule(
#         "", "", "", "", None, '', '',
#         '''Set the mode on files being executed by the local initialization files with the following command:''',
#         '',
#         '''Verify that local initialization files do not execute world-writable programs.

#         Check the system for world-writable files.

#         The following command will discover and print world-writable files. Run it once for each local partition [PART]: 

#         For all files listed, check for their presence in the local initialization files with the following commands:

#         Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

#         If any local initialization files are found to reference world-writable files, this is a finding.''',
#         '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
#     )

#     assert str(stig_rule._getRequiredFields("Linux",
#                                             stig_rule.rule_fix_text)) == '[]'


# def test_get_required_field_windows_fix_1():
#     stig_rule = StigRule(
#         "", "", "", "", None, '', '',
#         '''Change the built-in Administrator account password at least every "60" days.

#         Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
#         https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
#         https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
#         '',
#         '''Review the password last set date for the built-in Administrator account.

#         Domain controllers:

#         Open "PowerShell".

#         Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

#         If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

#         Member servers and standalone or nondomain-joined systems:

#         Open "Command Prompt".

#         Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

#         (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

#         If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
#     )

#     assert str(stig_rule._getRequiredFields("Windows", stig_rule.check_content)) == '[]'

# def test_get_required_field_windows_check_1():
#     stig_rule = StigRule(
#         "SRG-OS-000076-GPOS-00044",
#         "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
#         "V-254239", "SV-254239r915618_rule", 10.0, "medium", "WN22-00-000020",
#         '''Change the built-in Administrator account password at least every "60" days.

#         Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
#         https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
#         https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
#         '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

#         Windows LAPS must be used  to change the built-in Administrator account password.''',
#         '''Review the password last set date for the built-in Administrator account.

#         Domain controllers:

#         Open "PowerShell".

#         Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

#         If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

#         Member servers and standalone or nondomain-joined systems:

#         Open "Command Prompt".

#         Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

#         (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

#         If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
#     )

#     assert str(stig_rule._getRequiredFields("Windows", stig_rule.check_content)) == '''[Command(Get-ADUser krbtgt -Property PasswordLastSet - [])]'''


def test_calculate_score_linux():
    stig_rule = StigRule("", "", "", "", 10.0, 'high', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "Very High"


def test_calculate_score_Windows():
    stig_rule = StigRule("", "", "", "", 10.0, "medium", "", '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "High"


def test_calculate_score_invalid():
    stig_rule = StigRule("", "", "", "", 10.0, "", "", '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "undefined"


def test_calculate_score_invalid_2():
    stig_rule = StigRule("", "", "", "", None, "medium", "", '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "undefined"


def test_parse_guide_linux():

    rule_fix_text = '''Configure the operating system to prevent informative messages from being presented at logon attempts.

    Add/Modify the "/etc/security/faillock.conf" file to match the following line:

    silent'''

    rule_description = '''By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.

    Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128'''

    rule_check_text = '''Note: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the "/etc/security/faillock.conf" file is configured to prevent informative messages from being presented at logon attempts:

$ sudo grep silent /etc/security/faillock.conf

silent

If the "silent" option is not set, is missing or commented out, this is a finding.'''

    stig_rule = parseGuide("app/tests/testFiles/test_linux_1.xml", "Linux")

    rule = stig_rule.stig_rule_dict['V-230341']

    assert str(rule.rule_name) == "SRG-OS-000021-GPOS-00005"
    assert str(
        rule.rule_title
    ) == "RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur."
    assert str(rule.vuln_id) == "V-230341"
    assert str(rule.rule_id) == "SV-230341r743978_rule"
    assert str(rule.rule_weight) == "10.0"
    assert str(rule.rule_severity) == "medium"
    assert str(rule.stig_id) == "RHEL-08-020019"
    assert str(rule.rule_fix_text) == str(rule_fix_text)
    assert str(rule.rule_description) == str(rule_description)
    assert str(rule.check_content) == str(rule_check_text)
    assert str(rule.category_score) == "High"


def test_parse_guide_windows():
    rule_fix_text = '''Remove unapproved shared accounts from the system.

Document required shared accounts with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.'''

    rule_description = '''Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate identification and authentication. There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.'''

    rule_check_text = '''Determine whether any shared accounts exist. If no shared accounts exist, this is NA.

Shared accounts, such as required by an application, may be approved by the organization. This must be documented with the Information System Security Officer (ISSO). Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.

If unapproved shared accounts exist, this is a finding.'''

    stig_rule = parseGuide("app/tests/testFiles/test_windows_1.xml", "Windows")

    rule = stig_rule.stig_rule_dict['V-254244']

    assert str(rule.rule_name) == "SRG-OS-000104-GPOS-00051"
    assert str(
        rule.rule_title
    ) == "Windows Server 2022 shared user accounts must not be permitted."
    assert str(rule.vuln_id) == "V-254244"
    assert str(rule.rule_id) == "SV-254244r848548_rule"
    assert str(rule.rule_weight) == "10.0"
    assert str(rule.rule_severity) == "medium"
    assert str(rule.stig_id) == "WN22-00-000070"
    assert str(rule.rule_fix_text) == str(rule_fix_text)
    assert str(rule.rule_description) == str(rule_description)
    assert str(rule.check_content) == str(rule_check_text)
    assert str(rule.category_score) == "High"


# def test_linux_script():
#     guide = parseGuide("app/tests/testFiles/test_linux_2.xml", "Linux")
    
#     linuxCreateScript(guide, user_input)
#     guide_name = guide.guide_name.split(".")[0]
#     expected_check_script = """#!/bin/bash
# mkdir AdminGuard
# cd AdminGuard
# touch check_script_logs.txt

# run_command() {
#     local cmd="$1"
#     local description="$2"

#     output=$(eval "$cmd" 2>&1)
#     if [ $? -ne 0 ]; then
#         echo "Error while running $description"
#         echo "Error while running $description" >> error_logs.txt
#     fi
# }
# echo sudo chmod test >> check_script_logs.txt
# run_command 'sudo chmod test >> check_script_logs.txt' 'Check Script for V-230309'
# echo sudo find yum -xdev -type f -perm -0002 -print install >> check_script_logs.txt
# run_command 'sudo find yum -xdev -type f -perm -0002 -print install >> check_script_logs.txt' 'Check Script for V-230309'
# echo sudo grep woo /home/*/.* >> check_script_logs.txt
# run_command 'sudo grep woo /home/*/.* >> check_script_logs.txt' 'Check Script for V-230309'
# echo sudo find / -fstype xfs -nogroup >> check_script_logs.txt
# run_command 'sudo find / -fstype xfs -nogroup >> check_script_logs.txt' 'Check Script for V-230327'
# echo sudo yum history list | more >> check_script_logs.txt
# run_command 'sudo yum history list | more >> check_script_logs.txt' 'Check Script for V-230222'
# """
#     expected_fix_script = """#!/bin/bash
# mkdir AdminGuard
# cd AdminGuard
# touch fix_script_logs.txt

# run_command() {
#     local cmd="$1"
#     local description="$2"

#     output=$(eval "$cmd" 2>&1)
#     if [ $? -ne 0 ]; then
#         echo "Error while running $description"
#         echo "Error while running $description" >> error_logs.txt
#     fi
# }
# echo sudo chmod test >> fix_script_logs.txt
# run_command 'sudo chmod test >> fix_script_logs.txt' 'Fix Script for V-230309'
# echo sudo find yum -xdev -type f -perm -0002 -print install >> fix_script_logs.txt
# run_command 'sudo find yum -xdev -type f -perm -0002 -print install >> fix_script_logs.txt' 'Fix Script for V-230309'
# echo sudo chmod 0755 woo >> fix_script_logs.txt
# run_command 'sudo chmod 0755 woo >> fix_script_logs.txt' 'Fix Script for V-230309'
# echo sudo chgrp yum install >> fix_script_logs.txt
# run_command 'sudo chgrp yum install >> fix_script_logs.txt' 'Fix Script for V-230327'
# """

#     expected_manual_check = """CHECK CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------

# """

#     expected_manual_fix = """FIX CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------
# V-230222
# Install the operating system patches or updated packages available from Red Hat within 30 days or sooner as local policy dictates.
# --------------------------------------------------------------

# """

#     try:
#         folder_path = os.path.join(os.getcwd(), "app", "out-files")
#         if os.path.exists(folder_path) and os.path.isdir(folder_path):
#             items = os.listdir(folder_path)

#             files = [
#                 item for item in items
#                 if os.path.isfile(os.path.join(folder_path, item))
#             ]

#             if len(files) > 0:
#                 for file in files:
#                     if file.endswith(".ps1") or file.endswith(".txt") or file.endswith(".zip"):
#                         if file.startswith(guide_name):
#                             if file == "test_linux_2-CheckScript.ps1":
#                                 with open("test_linux_2-CheckScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_check_script
#                             elif file == "test_linux_2-FixScript.ps1":
#                                 with open("test_linux_2-FixScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_fix_script
#                             elif file == "test_linux_2-ManualCheck.txt":
#                                 with open("test_linux_2-ManualCheck.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_check
#                             elif file == "test_linux_2-ManualFix.txt":
#                                 with open("test_linux_2-ManualFix.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_fix
#                             elif file == "test_linux_2.zip":
#                                 zip_extract = os.mkdir("test_linux_2_zip")
#                                 zipfile.extractall(zip_extract)
#                                 os.chdir(zip_extract)
#                                 files = [
#                                     item for item in os.listdir()
#                                     if os.path.isfile(
#                                         os.path.join(zip_extract, item))
#                                 ]
#                                 if len(files) < 5:
#                                     for file in files:
#                                         if file == "test_linux_2-CheckScript.ps1":
#                                             assert True
#                                         elif file =="test_linux_2-FixScript.ps1":
#                                             assert True
#                                         elif file == "test_linux_2-ManualCheck.txt":
#                                             assert True
#                                         elif file == "test_linux_2-ManualFix.txt":
#                                             assert True
#                                         elif file == "updated_test_linux_2.xml":
#                                             assert True
#                                 else:
#                                     raise AssertionError(
#                                         "Assertion failed: Not all files were extracted from the zip file."
#                                     )

#             else:
#                 raise AssertionError(
#                     "Assertion failed: No files found in the folder.")
#         else:
#             raise AssertionError(
#                 f"The folder '{folder_path}' either doesn't exist or is not a directory."
#             )
#     except Exception:
#         raise AssertionError(
#             "Something went wrong while testing the script creation.")


# def test_windows_script():
#     guide = parseGuide("app/tests/testFiles/test_windows_2.xml", "Windows")
    
#     windowsCreateScript(guide, user_input)
#     guide_name = guide.guide_name.split(".")[0]
#     expected_check_script = """mkdir AdminGuard | out-null
# Set-Location AdminGuard
# New-Item -Name 'check_script_logs.txt' -ItemType 'file' | out-null

# function run_command {
#     param (
#         [string]$cmd,
#         [string]$description
#     )

#     $output = Invoke-Expression $cmd 2>&1
#     if ($LASTEXITCODE -ne 0) {
#         Write-Host "Error while running $description"
#         "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
#     }
# }
# Write-Output 'Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet' >> check_script_logs.txt
# run_command 'Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet >> check_script_logs.txt' 'Check Script for V-254239'
# Write-Output 'Net User [account name] | Find /i "Password Last Set"' >> check_script_logs.txt
# run_command 'Net User [account name] | Find /i "Password Last Set" >> check_script_logs.txt' 'Check Script for V-254239'
# Write-Output 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet' >> check_script_logs.txt
# run_command 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet >> check_script_logs.txt' 'Check Script for V-254243'
# """
#     expected_fix_script = """mkdir AdminGuard | out-null
# Set-Location AdminGuard
# New-Item -Name 'fix_script_logs.txt' -ItemType 'file' | out-null

# function run_command {
#     param (
#         [string]$cmd,
#         [string]$description
#     )

#     $output = Invoke-Expression $cmd 2>&1
#     if ($LASTEXITCODE -ne 0) {
#         Write-Host "Error while running $description"
#         "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
#     }
# }
# Write-Output 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet' >> fix_script_logs.txt
# run_command 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet >> fix_script_logs.txt' 'fix Script for V-254243'
# """

#     expected_manual_check = """CHECK CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------
# V-254244
# Determine whether any shared accounts exist. If no shared accounts exist, this is NA.

# Shared accounts, such as required by an application, may be approved by the organization. This must be documented with the Information System Security Officer (ISSO). Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.

# If unapproved shared accounts exist, this is a finding.
# --------------------------------------------------------------

# """

#     expected_manual_fix = """FIX CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------
# V-254239
# Change the built-in Administrator account password at least every "60" days.

# Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. 
# https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747  
# https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status
# --------------------------------------------------------------
# V-254244
# Remove unapproved shared accounts from the system.

# Document required shared accounts with the ISSO. Documentation must include the reason for the account, who has access to the account, and how the risk of using the shared account is mitigated to include monitoring account activity.
# --------------------------------------------------------------

# """

#     try:
#         folder_path = os.path.join(os.getcwd(), "app", "out-files")
#         if os.path.exists(folder_path) and os.path.isdir(folder_path):
#             items = os.listdir(folder_path)

#             files = [
#                 item for item in items
#                 if os.path.isfile(os.path.join(folder_path, item))
#             ]

#             if len(files) > 0:
#                 for file in files:
#                     if file.endswith(".ps1") or file.endswith(".txt") or file.endswith(".zip"):
#                         if file.startswith(guide_name):
#                             if file == "test_windows_2-CheckScript.ps1":
#                                 with open("test_windows_2-CheckScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_check_script
#                             elif file == "test_windows_2-FixScript.ps1":
#                                 with open("test_windows_2-FixScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_fix_script
#                             elif file == "test_windows_2-ManualCheck.txt":
#                                 with open("test_windows_2-ManualCheck.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_check
#                             elif file == "test_windows_2-ManualFix.txt":
#                                 with open("test_windows_2-ManualFix.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_fix
#                             elif file == "test_windows_2.zip":
#                                 zip_extract = os.mkdir("test_windows_2_zip")
#                                 zipfile.extractall(zip_extract)
#                                 os.chdir(zip_extract)
#                                 files = [
#                                     item for item in os.listdir()
#                                     if os.path.isfile(
#                                         os.path.join(zip_extract, item))
#                                 ]
#                                 if len(files) < 5:
#                                     for file in files:
#                                         if file == "test_windows_2-CheckScript.ps1":
#                                             assert True
#                                         elif file =="test_windows_2-FixScript.ps1":
#                                             assert True
#                                         elif file == "test_windows_2-ManualCheck.txt":
#                                             assert True
#                                         elif file == "test_windows_2-ManualFix.txt":
#                                             assert True
#                                         elif file == "updated_test_windows_2.xml":
#                                             assert True
#                                 else:
#                                     raise AssertionError(
#                                         "Assertion failed: Not all files were extracted from the zip file."
#                                     )
#             else:
#                 raise AssertionError(
#                     "Assertion failed: No files found in the folder.")
#         else:
#             raise AssertionError(
#                 f"The folder '{folder_path}' either doesn't exist or is not a directory."
#             )
#     except Exception:
#         raise AssertionError(
#             "Something went wrong while testing the script creation.")


# def test_linux_script_empty():
#     guide = parseGuide("app/tests/testFiles/test_linux_3.xml", "Linux")

#     linuxCreateScript(guide, user_input)
#     guide_name = guide.guide_name.split(".")[0]
#     expected_check_script = """#!/bin/bash
# mkdir AdminGuard
# cd AdminGuard
# touch check_script_logs.txt

# run_command() {
#     local cmd="$1"
#     local description="$2"

#     output=$(eval "$cmd" 2>&1)
#     if [ $? -ne 0 ]; then
#         echo "Error while running $description"
#         echo "Error while running $description" >> error_logs.txt
#     fi
# }
# """
#     expected_fix_script = """#!/bin/bash
# mkdir AdminGuard
# cd AdminGuard
# touch fix_script_logs.txt

# run_command() {
#     local cmd="$1"
#     local description="$2"

#     output=$(eval "$cmd" 2>&1)
#     if [ $? -ne 0 ]; then
#         echo "Error while running $description"
#         echo "Error while running $description" >> error_logs.txt
#     fi
# }
# """

#     expected_manual_check = """CHECK CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------

# """

#     expected_manual_fix = """FIX CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------

# """

#     try:
#         folder_path = os.path.join(os.getcwd(), "app", "out-files")
#         if os.path.exists(folder_path) and os.path.isdir(folder_path):
#             items = os.listdir(folder_path)

#             files = [
#                 item for item in items
#                 if os.path.isfile(os.path.join(folder_path, item))
#             ]

#             if len(files) > 0:
#                 for file in files:
#                     if file.endswith(".ps1") or file.endswith(".txt") or file.endswith(".zip"):
#                         if file.startswith(guide_name):
#                             if file == "test_linux_3-CheckScript.ps1":
#                                 with open("test_linux_3-CheckScript.ps1",
#                                             "r") as f:
#                                     assert f.read() == expected_check_script
#                             elif file == "test_linux_3-FixScript.ps1":
#                                 with open("test_linux_3-FixScript.ps1",
#                                             "r") as f:
#                                     assert f.read() == expected_fix_script
#                             elif file == "test_linux_3-ManualCheck.txt":
#                                 with open("test_linux_3-ManualCheck.txt",
#                                             "r") as f:
#                                     assert f.read() == expected_manual_check
#                             elif file == "test_linux_3-ManualFix.txt":
#                                 with open("test_linux_3-ManualFix.txt",
#                                             "r") as f:
#                                     assert f.read() == expected_manual_fix
#                             elif file == "test_linux_3.zip":
#                                 zip_extract = os.mkdir("test_linux_3_zip")
#                                 zipfile.extractall(zip_extract)
#                                 os.chdir(zip_extract)
#                                 files = [
#                                     item for item in os.listdir()
#                                     if os.path.isfile(
#                                         os.path.join(zip_extract, item))
#                                 ]
#                                 if len(files) < 5:
#                                     for file in files:
#                                         if file == "test_linux_3-CheckScript.ps1":
#                                             assert True
#                                         elif file =="test_linux_3-FixScript.ps1":
#                                             assert True
#                                         elif file == "test_linux_3-ManualCheck.txt":
#                                             assert True
#                                         elif file == "test_linux_3-ManualFix.txt":
#                                             assert True
#                                         elif file == "updated_test_linux_3.xml":
#                                             assert True
#                                 else:
#                                     raise AssertionError(
#                                         "Assertion failed: Not all files were extracted from the zip file."
#                                     )
#             else:
#                 raise AssertionError(
#                     "Assertion failed: No files found in the folder.")
#         else:
#             raise AssertionError(
#                 f"The folder '{folder_path}' either doesn't exist or is not a directory."
#             )
#     except Exception:
#         raise AssertionError(
#             "Something went wrong while testing the script creation.")


# def test_windows_script_empty():
#     guide = parseGuide("app/tests/testFiles/test_windows_3.xml", "Windows")
    
#     windowsCreateScript(guide, user_input)
#     guide_name = guide.guide_name.split(".")[0]
#     expected_check_script = """mkdir AdminGuard | out-null
# Set-Location AdminGuard
# New-Item -Name 'check_script_logs.txt' -ItemType 'file' | out-null

# function run_command {
#     param (
#         [string]$cmd,
#         [string]$description
#     )

#     $output = Invoke-Expression $cmd 2>&1
#     if ($LASTEXITCODE -ne 0) {
#         Write-Host "Error while running $description"
#         "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
#     }
# }
# """
#     expected_fix_script = """mkdir AdminGuard | out-null
# Set-Location AdminGuard
# New-Item -Name 'fix_script_logs.txt' -ItemType 'file' | out-null

# function run_command {
#     param (
#         [string]$cmd,
#         [string]$description
#     )

#     $output = Invoke-Expression $cmd 2>&1
#     if ($LASTEXITCODE -ne 0) {
#         Write-Host "Error while running $description"
#         "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
#     }
# }
# """

#     expected_manual_check = """CHECK CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------

# """

#     expected_manual_fix = """FIX CONTENT TO BE MANUALLY CHECKED
# --------------------------------------------------------------

# """

#     try:
#         folder_path = os.path.join(os.getcwd(), "app", "out-files")
#         if os.path.exists(folder_path) and os.path.isdir(folder_path):
#             items = os.listdir(folder_path)

#             files = [
#                 item for item in items
#                 if os.path.isfile(os.path.join(folder_path, item))
#             ]

#             if len(files) > 0:
#                 for file in files:
#                     if file.endswith(".ps1") or file.endswith(".txt") or file.endswith(".zip"):
#                         if file.startswith(guide_name):
#                             if file == "test_windows_3-CheckScript.ps1":
#                                 with open("test_windows_3-CheckScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_check_script
#                             elif file == "test_windows_3-FixScript.ps1":
#                                 with open("test_windows_3-FixScript.ps1",
#                                           "r") as f:
#                                     assert f.read() == expected_fix_script
#                             elif file == "test_windows_3-ManualCheck.txt":
#                                 with open("test_windows_3-ManualCheck.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_check
#                             elif file == "test_windows_3-ManualFix.txt":
#                                 with open("test_windows_3-ManualFix.txt",
#                                           "r") as f:
#                                     assert f.read() == expected_manual_fix
#                             elif file == "test_windows_3.zip":
#                                 zip_extract = os.mkdir("test_windows_3_zip")
#                                 zipfile.extractall(zip_extract)
#                                 os.chdir(zip_extract)
#                                 files = [
#                                     item for item in os.listdir()
#                                     if os.path.isfile(
#                                         os.path.join(zip_extract, item))
#                                 ]
#                                 if len(files) < 5:
#                                     for file in files:
#                                         if file == "test_windows_3-CheckScript.ps1":
#                                             assert True
#                                         elif file =="test_windows_3-FixScript.ps1":
#                                             assert True
#                                         elif file == "test_windows_3-ManualCheck.txt":
#                                             assert True
#                                         elif file == "test_windows_3-ManualFix.txt":
#                                             assert True
#                                         elif file == "updated_test_windows_3.xml":
#                                             assert True
#                                 else:
#                                     raise AssertionError(
#                                         "Assertion failed: Not all files were extracted from the zip file."
#                                     )

#             else:
#                 raise AssertionError(
#                     "Assertion failed: No files found in the folder.")
#         else:
#             raise AssertionError(
#                 f"The folder '{folder_path}' either doesn't exist or is not a directory."
#             )
#     except Exception:
#         raise AssertionError(
#             "Something went wrong while testing the script creation.")


def test_clear_created_files():
    folder_path = os.path.join(os.getcwd(), "app", "out-files")
    os.chdir(folder_path)
    folders = [
        item for item in os.listdir()
        if os.path.isfile(os.path.join(folder_path, item))
    ]
    for folder in folders:
        if folder.startswith("test"):
            os.chdir(folder)
            files = [
                item for item in os.listdir()
                if os.path.isfile(os.path.join(folder_path, item))
            ]
            for file in files:
                os.remove(file)
            os.chdir("..")
            os.rmdir(folder)
    
    for folder in folders:
        if folder.startswith("test"):
            raise AssertionError(
                "Assertion failed: Not all files were deleted.")
    
        assert True
