import os
import shutil
from ..app import *

root_dir = os.getcwd()


def compare_files(file1, file2):
    with open(file1, "r") as f:
        file1 = f.read()
        with open(file2, "r") as f:
            file2 = f.read()
            assert file1 == file2


def test_calculate_score_linux():
    stig_rule = StigRule("", "", "", "", "10.0", 'high', '', '', '', '', '',
                         '', '', '', '', '', '', '', '', '', '', '', '', '',
                         '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "Very High"


def test_calculate_score_Windows():
    stig_rule = StigRule("", "", "", "", "10.0", "medium", "", '', '', '', '',
                         '', '', '', '', '', '', '', '', '', '', '', '', '',
                         '', '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "High"


def test_calculate_score_invalid():
    stig_rule = StigRule("", "", "", "", "10.0", "", "", '', '', '', '', '',
                         '', '', '', '', '', '', '', '', '', '', '', '', '',
                         '', '', '', '', '', '', '')

    assert stig_rule._calculateScore() == "undefined"


def test_calculate_score_invalid_2():
    stig_rule = StigRule("", "", "", "", "", "medium", "", '', '', '', '', '',
                         '', '', '', '', '', '', '', '', '', '', '', '', '',
                         '', '', '', '', '', '', '')

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


def test_linux_script():
    shutil.copyfile("app/tests/testFiles/test_linux_2.xml",
                    "app/uploads/test_linux_2.xml")
    guide = parseGuide("app/tests/testFiles/test_linux_2.xml", "Linux")
    vuln_id_list = ["V-230341", "V-230222", "V-230327", "V-230309"]
    linuxCreateScript(guide, vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_linux_2/test_linux_2-CheckScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_2/test_linux_2-FixScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_2/test_linux_2-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_linux_2/test_linux_2-ManualFix.txt")
    compare_files(
        "app/out-files/test_linux_2/test_linux_2-CheckScript.sh",
        "app/tests/testFiles/check/test_linux_2/test_linux_2-CheckScript.sh")
    compare_files(
        "app/out-files/test_linux_2/test_linux_2-FixScript.sh",
        "app/tests/testFiles/check/test_linux_2/test_linux_2-FixScript.sh")
    compare_files(
        "app/out-files/test_linux_2/test_linux_2-ManualCheck.txt",
        "app/tests/testFiles/check/test_linux_2/test_linux_2-ManualCheck.txt")
    compare_files(
        "app/out-files/test_linux_2/test_linux_2-ManualFix.txt",
        "app/tests/testFiles/check/test_linux_2/test_linux_2-ManualFix.txt")


def test_linux_script_empty():
    shutil.copyfile("app/tests/testFiles/test_linux_3.xml",
                    "app/uploads/test_linux_3.xml")
    guide = parseGuide("app/tests/testFiles/test_linux_3.xml", "Linux")
    vuln_id_list = []
    linuxCreateScript(guide, vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_linux_3/test_linux_3-CheckScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_3/test_linux_3-FixScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_3/test_linux_3-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_linux_3/test_linux_3-ManualFix.txt")
    compare_files(
        "app/out-files/test_linux_3/test_linux_3-CheckScript.sh",
        "app/tests/testFiles/check/test_linux_3/test_linux_3-CheckScript.sh")
    compare_files(
        "app/out-files/test_linux_3/test_linux_3-FixScript.sh",
        "app/tests/testFiles/check/test_linux_3/test_linux_3-FixScript.sh")
    compare_files(
        "app/out-files/test_linux_3/test_linux_3-ManualCheck.txt",
        "app/tests/testFiles/check/test_linux_3/test_linux_3-ManualCheck.txt")
    compare_files(
        "app/out-files/test_linux_3/test_linux_3-ManualFix.txt",
        "app/tests/testFiles/check/test_linux_3/test_linux_3-ManualFix.txt")


def test_windows_script():
    shutil.copyfile("app/tests/testFiles/test_windows_2.xml",
                    "app/uploads/test_windows_2.xml")
    guide = parseGuide("app/tests/testFiles/test_windows_2.xml", "Windows")
    vuln_id_list = ["V-254239", "V-254243", "V-254244"]
    windowsCreateScript(guide, vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_windows_2/test_windows_2-CheckScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_2/test_windows_2-FixScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_2/test_windows_2-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_windows_2/test_windows_2-ManualFix.txt")
    compare_files(
        "app/out-files/test_windows_2/test_windows_2-CheckScript.ps1",
        "app/tests/testFiles/check/test_windows_2/test_windows_2-CheckScript.ps1"
    )
    compare_files(
        "app/out-files/test_windows_2/test_windows_2-FixScript.ps1",
        "app/tests/testFiles/check/test_windows_2/test_windows_2-FixScript.ps1"
    )
    compare_files(
        "app/out-files/test_windows_2/test_windows_2-ManualCheck.txt",
        "app/tests/testFiles/check/test_windows_2/test_windows_2-ManualCheck.txt"
    )
    compare_files(
        "app/out-files/test_windows_2/test_windows_2-ManualFix.txt",
        "app/tests/testFiles/check/test_windows_2/test_windows_2-ManualFix.txt"
    )


def test_windows_script_empty():
    shutil.copyfile("app/tests/testFiles/test_windows_3.xml",
                    "app/uploads/test_windows_3.xml")
    guide = parseGuide("app/tests/testFiles/test_windows_3.xml", "Windows")
    vuln_id_list = []
    windowsCreateScript(guide, vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_windows_3/test_windows_3-CheckScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_3/test_windows_3-FixScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_3/test_windows_3-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_windows_3/test_windows_3-ManualFix.txt")
    compare_files(
        "app/out-files/test_windows_3/test_windows_3-CheckScript.ps1",
        "app/tests/testFiles/check/test_windows_3/test_windows_3-CheckScript.ps1"
    )
    compare_files(
        "app/out-files/test_windows_3/test_windows_3-FixScript.ps1",
        "app/tests/testFiles/check/test_windows_3/test_windows_3-FixScript.ps1"
    )
    compare_files(
        "app/out-files/test_windows_3/test_windows_3-ManualCheck.txt",
        "app/tests/testFiles/check/test_windows_3/test_windows_3-ManualCheck.txt"
    )
    compare_files(
        "app/out-files/test_windows_3/test_windows_3-ManualFix.txt",
        "app/tests/testFiles/check/test_windows_3/test_windows_3-ManualFix.txt"
    )


def test_linux_generate_xml():
    shutil.copyfile("app/tests/testFiles/test_linux_2.xml",
                    "app/uploads/test_linux_2.xml")
    guide = parseGuide("app/tests/testFiles/test_linux_2.xml", "Linux")

    guide.stig_rule_dict["V-230341"].rule_title = "A"
    guide.stig_rule_dict["V-230341"].rule_fix_text = "A"
    guide.stig_rule_dict["V-230341"].rule_description = "A"
    guide.stig_rule_dict["V-230341"].check_content = "A"

    guide.stig_rule_dict["V-230222"].rule_title = "B"
    guide.stig_rule_dict["V-230222"].rule_fix_text = "B"
    guide.stig_rule_dict["V-230222"].rule_description = "B"
    guide.stig_rule_dict["V-230222"].check_content = "B"

    guide.stig_rule_dict["V-230327"].rule_title = "C"
    guide.stig_rule_dict["V-230327"].rule_fix_text = "C"
    guide.stig_rule_dict["V-230327"].rule_description = "C"
    guide.stig_rule_dict["V-230327"].check_content = "C"

    generateXml(guide)

    assert os.path.isfile(
        "app/out-files/test_linux_2/updated-test_linux_2.xml")
    compare_files(
        "app/out-files/test_linux_2/updated-test_linux_2.xml",
        "app/tests/testFiles/check/test_linux_2/updated-test_linux_2.xml")


def test_windows_generate_xml():
    shutil.copyfile("app/tests/testFiles/test_windows_2.xml",
                    "app/uploads/test_windows_2.xml")
    guide = parseGuide("app/tests/testFiles/test_windows_2.xml", "Windows")

    guide.stig_rule_dict["V-254239"].rule_title = "A"
    guide.stig_rule_dict["V-254239"].rule_fix_text = "A"
    guide.stig_rule_dict["V-254239"].rule_description = "A"
    guide.stig_rule_dict["V-254239"].check_content = "A"

    guide.stig_rule_dict["V-254243"].rule_title = "B"
    guide.stig_rule_dict["V-254243"].rule_fix_text = "B"
    guide.stig_rule_dict["V-254243"].rule_description = "B"
    guide.stig_rule_dict["V-254243"].check_content = "B"

    generateXml(guide)

    assert os.path.isfile(
        "app/out-files/test_windows_2/updated-test_windows_2.xml")
    compare_files(
        "app/out-files/test_windows_2/updated-test_windows_2.xml",
        "app/tests/testFiles/check/test_windows_2/updated-test_windows_2.xml")


def test_linux_zip_file_generate():
    shutil.copyfile("app/tests/testFiles/test_linux_4.xml",
                    "app/uploads/test_linux_4.xml")
    guide = parseGuide("app/tests/testFiles/test_linux_4.xml", "Linux")
    vuln_id_list = []

    linuxCreateScript(guide, vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_linux_4/test_linux_4-CheckScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_4/test_linux_4-FixScript.sh")
    assert os.path.isfile(
        "app/out-files/test_linux_4/test_linux_4-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_linux_4/test_linux_4-ManualFix.txt")

    generateXml(guide)

    assert os.path.isfile(
        "app/out-files/test_linux_4/updated-test_linux_4.xml")

    generateZip(guide)

    assert os.path.isfile("app/out-files/test_linux_4/test_linux_4.zip")


def test_windows_zip_file_generate():
    shutil.copyfile("app/tests/testFiles/test_windows_4.xml",
                    "app/uploads/stig/test_windows_4.xml")
    guide = parseGuide("app/tests/testFiles/test_windows_4.xml", "Windows")
    Vuln_id_list = []

    windowsCreateScript(guide, Vuln_id_list)

    assert os.path.isfile(
        "app/out-files/test_windows_4/test_windows_4-CheckScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_4/test_windows_4-FixScript.ps1")
    assert os.path.isfile(
        "app/out-files/test_windows_4/test_windows_4-ManualCheck.txt")
    assert os.path.isfile(
        "app/out-files/test_windows_4/test_windows_4-ManualFix.txt")

    generateXml(guide)

    assert os.path.isfile(
        "app/out-files/test_windows_4/updated-test_windows_4.xml")

    generateZip(guide)

    assert os.path.isfile("app/out-files/test_windows_4/test_windows_4.zip")


def test_remove_files():
    for folder in os.listdir(os.path.join(root_dir, "app", "out-files")):
        if folder.startswith("test"):
            shutil.rmtree(os.path.join(root_dir, "app", "out-files", folder))
    for file in os.listdir(os.path.join(root_dir, "app", "uploads")):
        if file.startswith("test"):
            os.remove(os.path.join(root_dir, "app", "uploads", file))
    for folder in os.listdir(os.path.join(root_dir, "app", "out-files",
                                          "zip")):
        if folder.startswith("test"):
            shutil.rmtree(
                os.path.join(root_dir, "app", "out-files", "zip", folder))
