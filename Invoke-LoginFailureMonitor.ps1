# Author: Logan Bennett
# Date: 04/09/2026

# I wrote this script to defend against likely brute force identity attacks. It's not perfect but it works very well for server use
# Edit the variables under the Variables section to modify it's behavior
# Run the script as Local System or a service account (recommended) that has access to the EWT Security logs and to modify firewall rules
# Important: In order for this script to work properly, you need to configure your firewall to Block inbound connections by default

# TODO: Add a timeout that removes the block after a set period of time. Can possibly be acheived by correlating firewall creation time or a new xml object with date objects for reference
# TODO: Add functionality to block password spray attacks by correlating source ip and logon type with different usernames

[CmdletBinding()]
Param()


## Functions ##

# Parses the targeted account from event logs
Function Get-TargetedAccount
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$LogMessage
    )

    $Matches = $LogMessage | Select-String -AllMatches "Account Name:\s+([a-zA-Z0-9\-_@$]+)"
    $Result = ($Matches.Matches.Groups | Where-Object {$_.Name -eq 1} | Where-Object {$_.Value -notlike "$(hostname)$"}).Value

    Return $Result
}

# Parses the source ip from event logs
Function Get-SourceIp
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$LogMessage
    )

    $Matches = $LogMessage | Select-String -AllMatches "Source Network Address:\s(([0-9]+\.){3}[0-9]+)"
    $Result = ($Matches.Matches.Groups | Where-Object {$_.Name -eq 1} | Where-Object {$_.Name -eq 1}).Value

    Return $Result
}

# Parses the logon type from event logs
Function Get-LogonType
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$LogMessage
    )

    $Matches = $LogMessage | Select-String -AllMatches "Logon Type:\s+([0-9]{1,2})"
    $Result = ($Matches.Matches.Groups | Where-Object {$_.Name -eq 1} | Where-Object {$_.Name -eq 1}).Value

    Return $Result
}

# Parses the user domain in the event logs
Function Get-UserDomain
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$LogMessage
    )

    $Matches = $LogMessage | Select-String -AllMatches "Account Domain:\s+([a-zA-Z0-9.\-_]+)"
    $Result = ($Matches.Matches.Groups | Where-Object {$_.Name -eq 1} | Select -Last 1).Value

    Return $Result
}

# Adds a inbound firewall block rule
Function Add-BlockRule
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$RemoteIP,

        [Parameter(Mandatory=$True)]
        [String]$RuleName
    )

    New-NetFirewallRule -Direction Inbound -RemoteAddress $RemoteIP -Action Block -Name $RuleName -DisplayName $RuleName
}

## Variables ##

# Edit these to your liking
$MaxLoginFailureAttempts = 5
$IPWhitelist = @('127.0.0.1')
$DetectionTime = 30   # In Minutes
$WaitTime = 90       # In Seconds


## Main Monitoring Code ##
while ($True)
{
    # Write-Host "TESTING: " Starting loop"
    $CurrentTime = Get-Date
    $Timespan = $CurrentTime.AddMinutes(-$DetectionTime)
    try
    {
        # Write-Host "TESTING: " Query event logs"
        $Messages = Get-WinEvent -FilterHashtable @{Logname="Security"; Id=4625; StartTime=$Timespan} -ErrorAction Stop | Select -ExpandProperty Message
    }
    catch [System.Exception]
    {
        Write-Verbose "No events found this iteration."
    }

    if ($Messages)
    {
        # Write-Host "TESTING: " Starting main checks"
        $LoginAttemptStorageArray = @()
        foreach ($Message in $Messages)
        {
            # Write-Host "TESTING: " Parsing a message"
            $AccountName = Get-TargetedAccount -LogMessage $Message
            $SourceIp = Get-SourceIp -LogMessage $Message
            $TargetDomain = Get-UserDomain -LogMessage $Message
            $LogonType = Get-LogonType -LogMessage $Message

            $Object = [PSCustomObject]@{
                TargetAccount = $AccountName
                TargetDomain = $TargetDomain
                SourceIp = $SourceIp
                LogonType = $LogonType
            }

            $LoginAttemptStorageArray += $Object
        }

        # Write-Host "TESTING: " Grouping the array"
        $Grouping = $LoginAttemptStorageArray | Where-Object {$_.SourceIp -ne $Null -and $_.SourceIp -notin $IPWhitelist} | Group -Property TargetAccount,TargetDomain,SourceIp,LogonType
        
        # Write-Host "TESTING: " Printing grouping"
        if (-not $Grouping)
        {
            # Write-Host "TESTING: " Grouping has no data"
        }
        $Grouping

        foreach ($Group in $Grouping)
        {
            # Write-Host "TESTING: " Calculating group count"
            if ($Group.count -gt $MaxLoginFailureAttempts)
            {
                $OffenseSource = $Group.Group.SourceIp | Select -Unique
                $FirewallRuleName = "PSFailMod_BLOCK_$OffenseSource"

                if (-not (Get-NetFirewallRule -PolicyStore "PersistentStore" -Name $FirewallRuleName -ErrorAction SilentlyContinue))
                {
                    Add-BlockRule -RemoteIP $OffenseSource -RuleName $FirewallRuleName
                    Write-Host "$OffenseSource blocked from all inbound connections."
                }
                else
                {
                    Write-Verbose "$FirewallRuleName already exists"
                }
            }
        }
    }

    # Write-Host "TESTING: " Starting sleep"
    Start-Sleep -Seconds 90
}

