from app import *
from app.script.admin_guard import *


def test_get_required_field_linux_check():
    stig_rule = StigRule(
        "SRG-OS-000480-GPOS-00227",
        "Local RHEL 8 initialization files must not execute world-writable programs.",
        "V-230309", "SV-230309r627750_rule", 10.0, 'medium', 'RHEL-08-010660',
        '''Set the mode on files being executed by the local initialization files with the following command:
        $ sudo chmod test
        $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]
        $ sudo chmod 0755 <file>
        $ sudo ssh-keygen -y -f /path/to/file
        $ sudo rm /[path]/[to]/[file]/.shosts''',
        '''If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.''',
        '''Verify that local initialization files do not execute world-writable programs.

        Check the system for world-writable files.

        The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
        $ sudo chmod test
        $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]

        For all files listed, check for their presence in the local initialization files with the following commands:

        Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

        $ sudo grep <file> /home/*/.*
        $ sudo ssh-keygen -y -f /path/to/file
        $ sudo rm /[path]/[to]/[file]/.shosts

        If any local initialization files are found to reference world-writable files, this is a finding.'''
    )

    assert str(
        stig_rule._getRequiredFields("Linux", stig_rule.check_content)
    ) == '''[Command(sudo chmod test - []), Command(sudo find [PART] -xdev -type f -perm -0002 -print [Test] - ['[PART]', '[Test]']), Command(sudo grep <file> /home/*/.* - ['<file>']), Command(sudo ssh-keygen -y -f /path/to/file - ['/path/to/file']), Command(sudo rm /[path]/[to]/[file]/.shosts - ['/[path]/[to]/[file]/'])]'''


def test_get_required_field_linux_fix():
    stig_rule = StigRule(
        "SRG-OS-000480-GPOS-00227",
        "Local RHEL 8 initialization files must not execute world-writable programs.",
        "V-230309", "SV-230309r627750_rule", 10.0, 'medium', 'RHEL-08-010660',
        '''Set the mode on files being executed by the local initialization files with the following command:
        $ sudo chmod test
        $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]
        $ sudo chmod 0755 <file>
        $ sudo ssh-keygen -y -f /path/to/file
        $ sudo rm /[path]/[to]/[file]/.shosts''',
        '''If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.''',
        '''Verify that local initialization files do not execute world-writable programs.

        Check the system for world-writable files.

        The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
        $ sudo chmod test
        $ sudo find [PART] -xdev -type f -perm -0002 -print [Test]

        For all files listed, check for their presence in the local initialization files with the following commands:

        Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

        $ sudo grep <file> /home/*/.*
        $ sudo ssh-keygen -y -f /path/to/file
        $ sudo rm /[path]/[to]/[file]/.shosts

        If any local initialization files are found to reference world-writable files, this is a finding.'''
    )

    assert str(
        stig_rule._getRequiredFields("Linux", stig_rule.rule_fix_text)
    ) == '''[Command(sudo chmod test - []), Command(sudo find [PART] -xdev -type f -perm -0002 -print [Test] - ['[PART]', '[Test]']), Command(sudo chmod 0755 <file> - ['<file>']), Command(sudo ssh-keygen -y -f /path/to/file - ['/path/to/file']), Command(sudo rm /[path]/[to]/[file]/.shosts - ['/[path]/[to]/[file]/'])]'''


def test_get_required_field_windows_fix_1():
    stig_rule = StigRule(
        "SRG-OS-000076-GPOS-00044",
        "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
        "V-254239", "SV-254239r915618_rule", 10.0, "medium", "WN22-00-000020",
        '''Change the built-in Administrator account password at least every "60" days.

        Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
        https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747  
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
        '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

        Windows LAPS must be used  to change the built-in Administrator account password.''',
        '''Review the password last set date for the built-in Administrator account.

        Domain controllers:

        Open "PowerShell".

        Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

        Member servers and standalone or nondomain-joined systems:

        Open "Command Prompt".

        Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

        (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
    )


def test_get_required_field_windows_check_1():
    stig_rule = StigRule(
        "SRG-OS-000076-GPOS-00044",
        "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
        "V-254239", "SV-254239r915618_rule", 10.0, "medium", "WN22-00-000020",
        '''Change the built-in Administrator account password at least every "60" days.

        Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
        https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747  
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
        '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

        Windows LAPS must be used  to change the built-in Administrator account password.''',
        '''Review the password last set date for the built-in Administrator account.

        Domain controllers:

        Open "PowerShell".

        Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

        Member servers and standalone or nondomain-joined systems:

        Open "Command Prompt".

        Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

        (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
    )


def test_calculate_score_linux():
    stig_rule = StigRule(
        "SRG-OS-000033-GPOS-00014",
        "RHEL 8 must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.",
        "V-230223", "SV-230223r877398_rule", 10.0, 'high', 'RHEL-08-010020',
        '''Configure the operating system to implement DoD-approved encryption by following the steps below:

        To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel boot parameters during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

        Enable FIPS mode after installation (not strict FIPS compliant) with the following command:

        $ sudo fips-mode-setup --enable

        Reboot the system for the changes to take effect.''',
        '''Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the Federal Government since this provides assurance they have been tested and validated.

        RHEL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries.  The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

        The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.

        Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000125-GPOS-00065, SRG-OS-000396-GPOS-00176, SRG-OS-000423-GPOS-00187, SRG-OS-000478-GPOS-00223''',
        '''Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.

        Check to see if FIPS mode is enabled with the following command:

        $ fips-mode-setup --check

        FIPS mode is enabled

        If FIPS mode is "enabled", check to see if the kernel boot parameter is configured for FIPS mode with the following command:

        $ sudo grub2-editenv list | grep fips kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

        If the kernel boot parameter is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:

        $ sudo cat /proc/sys/crypto/fips_enabled

        1

        If FIPS mode is not "on", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of "1" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'''
    )

    assert stig_rule._calculateScore() == "Very High"


def test_calculate_score_Windows():
    stig_rule = StigRule(
        "SRG-OS-000076-GPOS-00044",
        "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
        "V-254239", "SV-254239r915618_rule", 10.0, "medium", "WN22-00-000020",
        '''Change the built-in Administrator account password at least every "60" days.

        Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
        https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
        '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

        Windows LAPS must be used  to change the built-in Administrator account password.''',
        '''Review the password last set date for the built-in Administrator account.

        Domain controllers:

        Open "PowerShell".

        Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

        Member servers and standalone or nondomain-joined systems:

        Open "Command Prompt".

        Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

        (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
    )

    assert stig_rule._calculateScore() == "High"


def test_calculate_score_invalid_1():
    stig_rule = StigRule(
        "SRG-OS-000076-GPOS-00044",
        "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
        "V-254239", "SV-254239r915618_rule", 10.0, "", "WN22-00-000020",
        '''Change the built-in Administrator account password at least every "60" days.

        Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. 
        https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
        '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

        Windows LAPS must be used  to change the built-in Administrator account password.''',
        '''Review the password last set date for the built-in Administrator account.

        Domain controllers:

        Open "PowerShell".

        Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

        Member servers and standalone or nondomain-joined systems:

        Open "Command Prompt".

        Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

        (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
    )

    assert stig_rule._calculateScore() == "undefined"


def test_calculate_score_invalid_2():
    stig_rule = StigRule(
        "SRG-OS-000076-GPOS-00044",
        "Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days.",
        "V-254239", "SV-254239r915618_rule", None, "medium", "WN22-00-000020",
        '''Change the built-in Administrator account password at least every "60" days.

        Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. 
        https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status''',
        '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

        Windows LAPS must be used  to change the built-in Administrator account password.''',
        '''Review the password last set date for the built-in Administrator account.

        Domain controllers:

        Open "PowerShell".

        Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet".

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.

        Member servers and standalone or nondomain-joined systems:

        Open "Command Prompt".

        Enter "Net User [account name] | Find /i "Password Last Set"", where [account name] is the name of the built-in administrator account.

        (The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

        If the "PasswordLastSet" date is greater than "60" days old, this is a finding.'''
    )

    assert stig_rule._calculateScore() == "undefined"


# def test_parse_guide():
#     print("parse_guide")

# def test_create_script():
#     print("create_script")

# def test_linux_script():
#     print("test_linux_script")

# def test_windows_script():
#     print("test_windows_script")
