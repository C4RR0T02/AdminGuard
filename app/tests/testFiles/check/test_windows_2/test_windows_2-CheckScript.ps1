mkdir AdminGuard | out-null
Set-Location AdminGuard
New-Item -Name 'check_script_logs.txt' -ItemType 'file' | out-null

function run_command {
    param (
        [string]$cmd,
        [string]$description
    )

    $output = Invoke-Expression $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error while running $description"
        "Error while running $description" | Out-File -Append -FilePath "error_logs.txt"
    }
}
Write-Output 'Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet' >> check_script_logs.txt
run_command 'Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | Ft Name, SID, PasswordLastSet >> check_script_logs.txt' 'Check Script for V-254239'
Write-Output 'Net User [account name] | Find /i "Password Last Set"' >> check_script_logs.txt
run_command 'Net User [account name] | Find /i "Password Last Set" >> check_script_logs.txt' 'Check Script for V-254239'
Write-Output 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet' >> check_script_logs.txt
run_command 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet >> check_script_logs.txt' 'Check Script for V-254243'
Write-Output 'Manual check required for V-254244' >> check_script_logs.txt
