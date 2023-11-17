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
