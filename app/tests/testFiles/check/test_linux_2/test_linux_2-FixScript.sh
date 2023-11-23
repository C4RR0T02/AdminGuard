#!/bin/bash
mkdir AdminGuard
cd AdminGuard
touch fix_script_logs.txt
touch manual_fix.txt

run_command() {
    local cmd="$1"
    local description="$2"

    output=$(eval "$cmd" 2>&1)
    if [ $? -ne 0 ]; then
        echo "Error while running $description"
        echo "Error while running $description" >> error_logs.txt
    fi
}
echo 'Manual fix required for V-230341' >> fix_script_logs.txt
echo 'Manual fix required for V-230222' >> fix_script_logs.txt
echo 'sudo chgrp <group> <file>' >> fix_script_logs.txt
run_command 'sudo chgrp <group> <file> >> fix_script_logs.txt' 'Fix Script for V-230327'
echo 'sudo chmod 600 test' >> fix_script_logs.txt
run_command 'sudo chmod 600 test >> fix_script_logs.txt' 'Fix Script for V-230309'
echo 'sudo find [PART] -xdev -type f -perm -0002 -print [Test]' >> fix_script_logs.txt
run_command 'sudo find [PART] -xdev -type f -perm -0002 -print [Test] >> fix_script_logs.txt' 'Fix Script for V-230309'
echo 'sudo chmod 0755 <file>' >> fix_script_logs.txt
run_command 'sudo chmod 0755 <file> >> fix_script_logs.txt' 'Fix Script for V-230309'
