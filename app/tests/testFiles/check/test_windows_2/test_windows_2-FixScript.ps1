mkdir AdminGuard | out-null
Set-Location AdminGuard
New-Item -Name 'fix_script_logs.txt' -ItemType 'file' | out-null

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
Write-Output 'Manual fix required for V-254239' >> fix_script_logs.txt
Write-Output 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet' >> fix_script_logs.txt
run_command 'Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet >> fix_script_logs.txt' 'Fix Script for V-254243'
Write-Output 'Manual fix required for V-254244' >> fix_script_logs.txt
