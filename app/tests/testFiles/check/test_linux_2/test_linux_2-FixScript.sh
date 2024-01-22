#! /bin/bash
mkdir AdminGuard
cd AdminGuard
touch fix_script_logs.txt
touch manual_fix.txt

echo 'Manual fix required for V-230341' >> fix_script_logs.txt
echo 'Manual fix required for V-230222' >> fix_script_logs.txt
echo 'sudo chgrp <group> <file>' >> fix_script_logs.txt
sudo chgrp <group> <file> >> fix_script_logs.txt || echo "Error while running Fix Script for V-230327" >> error_logs.txt
echo 'sudo chmod 600 test' >> fix_script_logs.txt
sudo chmod 600 test >> fix_script_logs.txt || echo "Error while running Fix Script for V-230309" >> error_logs.txt
echo 'sudo find [PART] -xdev -type f -perm -0002 -print [Test]' >> fix_script_logs.txt
sudo find [PART] -xdev -type f -perm -0002 -print [Test] >> fix_script_logs.txt || echo "Error while running Fix Script for V-230309" >> error_logs.txt
echo 'sudo chmod 0755 <file>' >> fix_script_logs.txt
sudo chmod 0755 <file> >> fix_script_logs.txt || echo "Error while running Fix Script for V-230309" >> error_logs.txt
