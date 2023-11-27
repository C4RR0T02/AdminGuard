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
