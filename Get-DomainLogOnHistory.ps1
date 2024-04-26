param (
    [Parameter(Mandatory=$false)]
    [string]$username,
    [Parameter(Mandatory=$false)]
    [datetime]$startdate,
    [Parameter(Mandatory=$false)]
    [datetime]$enddate,
    [Parameter(Mandatory=$false)]
    [switch]$h = $false
)

if ($h -or (-not $username)) {
    Write-Host "Usage: .\script.ps1 -username <username> [-startdate <startdate>] [-enddate <enddate>]"
    Write-Host "       -username: Specify the username whose logon history you want to view."
    Write-Host "       -startdate: Optional. Specify the start date for the logon history. If not provided, the current date is used."
    Write-Host "       -enddate: Optional. Specify the end date for the logon history. If not provided, two days before the start date is used."
    Write-Host "       -h, --help: Display this help message."
    return
}

if (-not $startdate) {
    $startdate = Get-Date
}

if (-not $enddate) {
    $enddate = $startdate.AddDays(-2)
}

$DCs = Get-ADDomainController -Filter *

foreach ($DC in $DCs){
    $logonevents = Get-Eventlog -LogName Security -InstanceID 4624 -after $enddate -before $startdate -ComputerName $dc.HostName |
                   Where-Object {($_.ReplacementStrings[5] -notlike '*$') -and ($_.ReplacementStrings[5] -like "*$username*")}

    foreach ($event in $logonevents){
        # Remote (Logon Type 10)
        if ($event.ReplacementStrings[8] -eq 10){
            write-host "Type 10: Remote Logon`tDate: "$event.TimeGenerated "`tStatus: Success`tUser: "$event.ReplacementStrings[5] "`tWorkstation: "$event.ReplacementStrings[11] "`tIP Address: "$event.ReplacementStrings[18] "`tDC Name: " $dc.Name
        }
        # Network(Logon Type 3)
        if ($event.ReplacementStrings[8] -eq 3){
            write-host "Type 3: Network Logon`tDate: "$event.TimeGenerated "`tStatus: Success`tUser: "$event.ReplacementStrings[5] "`tWorkstation: "$event.ReplacementStrings[11] "`tIP Address: "$event.ReplacementStrings[18] "`tDC Name: " $dc.Name
        }
    }
}
