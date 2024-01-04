import os
import shutil
from app.script.template_gen import *

# Create upload and download folders if they don't exist
upload_folder = os.path.join('app', 'uploads')
if not os.path.isdir(upload_folder):
    os.mkdir(upload_folder)
if not os.path.isdir(os.path.join(upload_folder, 'stig')):
    os.mkdir(os.path.join(upload_folder, 'stig'))
if not os.path.isdir(os.path.join(upload_folder, 'vatemplate')):
    os.mkdir(os.path.join(upload_folder, 'vatemplate'))

download_folder = os.path.join('app', 'out-files')
if not os.path.isdir(download_folder):
    os.mkdir(download_folder)


def compare_files(file1, file2):
    with open(file1, "r") as f:
        file1 = f.read()
        with open(file2, "r") as f:
            file2 = f.read()
            assert file1 == file2


def test_parse_template_linux():
    shutil.copyfile("app/tests/testFiles/test_linux_template_1.audit",
                    "app/uploads/vatemplate/test_linux_template_1.audit")
    template_name = os.path.join("app", "uploads", "vatemplate",
                                 "test_linux_template_1.audit")
    template = parseTemplate(template_name, "Linux")
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields["system"] == "Linux"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields["type"] == "RPM_CHECK"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "description"] == "RHEL-08-010001 - The RHEL 8 operating system must implement the Endpoint Security for Linux Threat Prevention tool."
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "info"] == "Adding endpoint security tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "solution"] == "Install and enable the latest McAfee ENSLTP package."
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "reference"] == "800-171|3.14.1,800-53|SI-2(2),800-53r5|SI-2(2),CAT|II,CCI|CCI-001233,CN-L3|8.1.4.4(e),CN-L3|8.1.10.5(a),CN-L3|8.1.10.5(b),CN-L3|8.5.4.1(b),CN-L3|8.5.4.1(d),CN-L3|8.5.4.1(e),CSF|ID.RA-1,CSF|PR.IP-12,DISA_Benchmark|RHEL_8_STIG,GDPR|32.1.b,HIPAA|164.306(a)(1),ITSG-33|SI-2(2),NESA|T7.6.2,NESA|T7.7.1,NIAv2|PR9,PCI-DSSv3.2.1|6.2,PCI-DSSv4.0|6.3,PCI-DSSv4.0|6.3.3,QCSC-v1|11.2,Rule-ID|SV-245540r754730_rule,STIG-ID|RHEL-08-010001,SWIFT-CSCv1|2.2,Vuln-ID|V-245540"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "see_also"] == "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V1R11_STIG.zip"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields[
            "rpm"] == "McAfeeTP-0.0.0-0"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields["operator"] == "gt"
    assert template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields["required"] == "YES"


def test_parse_template_windows():
    shutil.copyfile("app/tests/testFiles/test_windows_template_1.audit",
                    "app/uploads/vatemplate/test_windows_template_1.audit")
    template_name = os.path.join("app", "uploads", "vatemplate",
                                 "test_windows_template_1.audit")
    template = parseTemplate(template_name, "Windows")
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "type"] == "AUDIT_POWERSHELL"
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "description"] == "WN22-00-000020 - Windows Server 2022 passwords for the built-in Administrator account must be changed at least every 60 days."
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "info"] == '''The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

Windows LAPS must be used  to change the built-in Administrator account password.'''
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "solution"] == '''Change the built-in Administrator account password at least every '60' days.

Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status'''
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "reference"] == "800-171|3.5.2,800-53|IA-5(1)(d),800-53r5|IA-5(1)(d),CAT|II,CCI|CCI-000199,CN-L3|7.1.2.7(e),CN-L3|7.1.3.1(b),CSF|PR.AC-1,DISA_Benchmark|MS_Windows_Server_2022_STIG,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(2)(i),HIPAA|164.312(d),ISO/IEC-27001|A.9.4.3,ITSG-33|IA-5(1)(d),NESA|T5.2.3,NIAv2|AM20,NIAv2|AM21,QCSC-v1|5.2.2,QCSC-v1|13.2,Rule-ID|SV-254239r915618_rule,STIG-ID|WN22-00-000020,SWIFT-CSCv1|4.1,TBA-FIISB|26.2.2,Vuln-ID|V-254239"
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "see_also"] == "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V1R3_STIG.zip"
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "value_type"] == "POLICY_TEXT"
    assert template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "value_data"] == "No passwords older than 60 days"


def test_linux_generate_template():
    shutil.copyfile("app/tests/testFiles/test_linux_template_1.audit",
                    "app/uploads/vatemplate/test_linux_template_1.audit")
    template_name = os.path.join("app", "uploads", "vatemplate",
                                 "test_linux_template_1.audit")
    template = parseTemplate(template_name, "Linux")
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["system"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["type"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["description"] = "TEST"
    template.template_rule_dict[0][
        "V-245540"].dictionary_fields.dictionary_fields["info"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["solution"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["see_also"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["file"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["regex"] = "TEST"
    template.template_rule_dict[0][
        "V-230221"].dictionary_fields.dictionary_fields["expect"] = "TEST"
    gen_template(template)
    compare_files(
        "app/out-files/test_linux_template_1/test_linux_template_1-updated",
        "app/tests/testFiles/check/test_linux_template_1/test_linux_template_1-updated"
    )


def test_windows_generate_template():
    shutil.copyfile("app/tests/testFiles/test_windows_template_1.audit",
                    "app/uploads/vatemplate/test_windows_template_1.audit")
    template_name = os.path.join("app", "uploads", "vatemplate",
                                 "test_windows_template_1.audit")
    template = parseTemplate(template_name, "Windows")
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["type"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["description"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["info"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["solution"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["see_also"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["value_type"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields["value_data"] = "TEST"
    template.template_rule_dict[0][
        "V-254239"].dictionary_fields.dictionary_fields[
            "powershell_args"] = "TEST"
    gen_template(template)
    compare_files(
        "app/out-files/test_windows_template_1/test_windows_template_1-updated",
        "app/tests/testFiles/check/test_windows_template_1/test_windows_template_1-updated"
    )


def test_remove_files():
    for folder in os.listdir(os.path.join("app", "out-files")):
        if folder.startswith("test"):
            shutil.rmtree(os.path.join("app", "out-files", folder))
    for file in os.listdir(os.path.join("app", "uploads", "stig")):
        if file.startswith("test"):
            os.remove(os.path.join("app", "uploads", "stig", file))
    for file in os.listdir(os.path.join("app", "uploads", "vatemplate")):
        if file.startswith("test"):
            os.remove(os.path.join("app", "uploads", "vatemplate", file))
