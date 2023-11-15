#!/bin/bash
mkdir AdminGuard
cd AdminGuard
touch check_script_logs.txt
touch manual_check.txt

run_command() {
    local cmd="$1"
    local description="$2"

    output=$(eval "$cmd" 2>&1)
    if [ $? -ne 0 ]; then
        echo "Error while running $description"
        echo "Error while running $description" >> error_logs.txt
    fi
}
echo 'sudo grep silent /etc/security/faillock.conf' >> check_script_logs.txt
run_command 'sudo grep silent /etc/security/faillock.conf >> check_script_logs.txt' 'Check Script for V-230341'
echo 'sudo yum history list | more' >> check_script_logs.txt
run_command 'sudo yum history list | more >> check_script_logs.txt' 'Check Script for V-230222'
echo 'sudo find / -fstype xfs -nogroup' >> check_script_logs.txt
run_command 'sudo find / -fstype xfs -nogroup >> check_script_logs.txt' 'Check Script for V-230327'
echo 'sudo chmod test' >> check_script_logs.txt
run_command 'sudo chmod test >> check_script_logs.txt' 'Check Script for V-230309'
echo 'sudo find [PART] -xdev -type f -perm -0002 -print [Test]' >> check_script_logs.txt
run_command 'sudo find [PART] -xdev -type f -perm -0002 -print [Test] >> check_script_logs.txt' 'Check Script for V-230309'
echo 'sudo grep <file> /home/*/.*' >> check_script_logs.txt
run_command 'sudo grep <file> /home/*/.* >> check_script_logs.txt' 'Check Script for V-230309'
