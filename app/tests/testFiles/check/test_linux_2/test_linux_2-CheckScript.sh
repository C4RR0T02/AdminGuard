#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt
touch manual_check.txt

echo 'sudo grep silent /etc/security/faillock.conf' >> check_script_logs.txt
sudo grep silent /etc/security/faillock.conf >> check_script_logs.txt || echo "Error while running Check Script for V-230341" >> error_logs.txt
echo 'sudo yum history list | more' >> check_script_logs.txt
sudo yum history list | more >> check_script_logs.txt || echo "Error while running Check Script for V-230222" >> error_logs.txt
echo 'sudo find / -fstype xfs -nogroup' >> check_script_logs.txt
sudo find / -fstype xfs -nogroup >> check_script_logs.txt || echo "Error while running Check Script for V-230327" >> error_logs.txt
echo 'sudo chmod 600 test' >> check_script_logs.txt
sudo chmod 600 test >> check_script_logs.txt || echo "Error while running Check Script for V-230309" >> error_logs.txt
echo 'sudo find [PART] -xdev -type f -perm -0002 -print [Test]' >> check_script_logs.txt
sudo find [PART] -xdev -type f -perm -0002 -print [Test] >> check_script_logs.txt || echo "Error while running Check Script for V-230309" >> error_logs.txt
echo 'sudo grep <file> /home/*/.*' >> check_script_logs.txt
sudo grep <file> /home/*/.* >> check_script_logs.txt || echo "Error while running Check Script for V-230309" >> error_logs.txt
