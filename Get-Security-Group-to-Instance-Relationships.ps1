# PowerShell script to get all security groups and find instances using them
# Requires AWS CLI to be installed and configured

param(
    [string[]]$Regions = @("eu-west-1", "eu-west-2"),
    [switch]$Verbose
)

Write-Host "Starting security group analysis for regions: $($Regions -join ', ')" -ForegroundColor Green

# Track security groups with no instances
$unusedSecurityGroups = @()
$sgWithNetworkInterfaces = @()
$sgCompletelyUnused = @()

# For progress tracking in non-verbose mode
$totalSecurityGroups = 0
$processedSecurityGroups = 0

# First pass: count total security groups for progress bar
if (-not $Verbose) {
    Write-Host "Counting security groups..." -ForegroundColor Cyan
    foreach ($region in $Regions) {
        try {
            $securityGroups = aws ec2 describe-security-groups --region $region --query "SecurityGroups[*].GroupId" --output text
            if ($LASTEXITCODE -eq 0 -and ![string]::IsNullOrWhiteSpace($securityGroups)) {
                $sgIds = $securityGroups -split "`t" | Where-Object { $_.Trim() -ne "" }
                $totalSecurityGroups += $sgIds.Count
            }
        }
        catch {
            # Ignore errors during counting
        }
    }
    Write-Host "Found $totalSecurityGroups total security groups to analyze." -ForegroundColor Green
}

foreach ($region in $Regions) {
    if ($Verbose) {
        Write-Host "`nProcessing region: $region" -ForegroundColor Yellow
    }
      try {
        # Get all security groups in the region
        if ($Verbose) {
            Write-Host "Retrieving security groups from $region..." -ForegroundColor Cyan
        }
        $securityGroups = aws ec2 describe-security-groups --region $region --query "SecurityGroups[*].GroupId" --output text
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to retrieve security groups from region $region"
            continue
        }
          if ([string]::IsNullOrWhiteSpace($securityGroups)) {
            if ($Verbose) {
                Write-Host "No security groups found in region $region" -ForegroundColor Gray
            }
            continue
        }
        
        # Split the security group IDs (AWS CLI returns tab-separated values)
        $sgIds = $securityGroups -split "`t" | Where-Object { $_.Trim() -ne "" }
        
        if ($Verbose) {
            Write-Host "Found $($sgIds.Count) security groups in $region" -ForegroundColor Green
        }
          foreach ($sgId in $sgIds) {
            $sgId = $sgId.Trim()
            if ([string]::IsNullOrWhiteSpace($sgId)) { continue }
            
            # Update progress bar in non-verbose mode
            if (-not $Verbose) {
                $processedSecurityGroups++
                $percentComplete = [math]::Round(($processedSecurityGroups / $totalSecurityGroups) * 100, 1)
                Write-Progress -Activity "Analyzing Security Groups" -Status "Processing $sgId ($processedSecurityGroups of $totalSecurityGroups)" -PercentComplete $percentComplete
            }
            
            if ($Verbose) {
                Write-Host "`n  Checking instances for security group: $sgId" -ForegroundColor White
            }
            
            try {
                # Get instances using this security group
                $instances = aws ec2 describe-instances --filters "Name=instance.group-id,Values=$sgId" --query "Reservations[*].Instances[*].Tags[?Key=='Name'].Value" --output text --region $region
                
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Failed to query instances for security group $sgId in region $region"
                    continue
                }                if ([string]::IsNullOrWhiteSpace($instances)) {
                    if ($Verbose) {
                        Write-Host "    No instances found using security group $sgId" -ForegroundColor Gray
                    }
                    
                    # Check if security group is attached to network interfaces
                    if ($Verbose) {
                        Write-Host "    Checking network interfaces for security group $sgId..." -ForegroundColor DarkGray
                    }
                    $networkInterfaces = aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$sgId" --query "NetworkInterfaces[*].NetworkInterfaceId" --output text --region $region
                    
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "Failed to query network interfaces for security group $sgId in region $region"
                        continue
                    }
                    
                    $sgObject = [PSCustomObject]@{
                        Region = $region
                        SecurityGroupId = $sgId
                    }
                      if ([string]::IsNullOrWhiteSpace($networkInterfaces)) {
                        if ($Verbose) {
                            Write-Host "    No network interfaces found for security group $sgId" -ForegroundColor DarkGray
                        }
                        $sgCompletelyUnused += $sgObject
                    } else {
                        $niIds = $networkInterfaces -split "`t" | Where-Object { $_.Trim() -ne "" }
                        if ($Verbose) {
                            Write-Host "    Found $($niIds.Count) network interface(s) using security group $sgId" -ForegroundColor Yellow
                        }
                        $sgWithNetworkInterfaces += $sgObject
                    }
                    
                    # Add to general unused list for backward compatibility
                    $unusedSecurityGroups += $sgObject                } else {
                    # Split instance names (AWS CLI returns tab-separated values)
                    $instanceNames = $instances -split "`t" | Where-Object { $_.Trim() -ne "" }
                    if ($Verbose) {
                        Write-Host "    Found $($instanceNames.Count) instance(s):" -ForegroundColor Green
                        foreach ($instanceName in $instanceNames) {
                            $instanceName = $instanceName.Trim()
                            if (![string]::IsNullOrWhiteSpace($instanceName)) {
                                Write-Host "      - $instanceName" -ForegroundColor Cyan
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error querying instances for security group $sgId`: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error processing region $region`: $($_.Exception.Message)"    }
}

# Complete the progress indicator for non-verbose mode
if (-not $Verbose) {
    Write-Progress -Activity "Analyzing Security Groups" -Completed
}

Write-Host "`nSecurity group analysis completed!" -ForegroundColor Green

# Only show detailed sections in verbose mode
if ($Verbose) {
    # Output summary of unused security groups
    Write-Host "`n" + "="*80 -ForegroundColor Magenta
    Write-Host "SUMMARY: Security Groups with No EC2 Instances" -ForegroundColor Magenta
    Write-Host "="*80 -ForegroundColor Magenta

    if ($unusedSecurityGroups.Count -eq 0) {
        Write-Host "All security groups are currently in use by EC2 instances." -ForegroundColor Green
    } else {
        Write-Host "Found $($unusedSecurityGroups.Count) security group(s) with no EC2 instances attached." -ForegroundColor Yellow
    }

    # Output completely unused security groups
    Write-Host "`n" + "-"*80 -ForegroundColor Red
    Write-Host "Security Groups with NO Instances AND NO Network Interfaces (Safe to Delete)" -ForegroundColor Red
    Write-Host "-"*80 -ForegroundColor Red

    if ($sgCompletelyUnused.Count -eq 0) {
        Write-Host "No completely unused security groups found." -ForegroundColor Green
    } else {
        Write-Host "Found $($sgCompletelyUnused.Count) security group(s) that are completely unused:" -ForegroundColor Red
        
        # Group by region for better display
        $groupedCompletelyUnused = $sgCompletelyUnused | Group-Object -Property Region
        
        foreach ($regionGroup in $groupedCompletelyUnused) {
            Write-Host "`nRegion: $($regionGroup.Name)" -ForegroundColor Cyan
            foreach ($sg in $regionGroup.Group) {
                Write-Host "  - $($sg.SecurityGroupId)" -ForegroundColor White
            }
        }
          Write-Host "`nPlain list for scripting (completely unused):" -ForegroundColor Gray
        foreach ($sg in $sgCompletelyUnused) {
            Write-Host "$($sg.Region):$($sg.SecurityGroupId) [SAFE-TO-DELETE]" -ForegroundColor DarkRed
        }
    }

    # Output security groups with network interfaces
    Write-Host "`n" + "-"*80 -ForegroundColor Yellow
    Write-Host "Security Groups with NO Instances BUT WITH Network Interfaces (Review Before Deleting)" -ForegroundColor Yellow
    Write-Host "-"*80 -ForegroundColor Yellow

    if ($sgWithNetworkInterfaces.Count -eq 0) {
        Write-Host "No security groups found with network interfaces but no instances." -ForegroundColor Green
    } else {
        Write-Host "Found $($sgWithNetworkInterfaces.Count) security group(s) attached to network interfaces:" -ForegroundColor Yellow
        
        # Group by region for better display
        $groupedWithNI = $sgWithNetworkInterfaces | Group-Object -Property Region
        
        foreach ($regionGroup in $groupedWithNI) {
            Write-Host "`nRegion: $($regionGroup.Name)" -ForegroundColor Cyan
            foreach ($sg in $regionGroup.Group) {
                Write-Host "  - $($sg.SecurityGroupId)" -ForegroundColor White
            }
        }    Write-Host "`nPlain list for scripting (with network interfaces):" -ForegroundColor Gray
        foreach ($sg in $sgWithNetworkInterfaces) {
            Write-Host "$($sg.Region):$($sg.SecurityGroupId) [HAS-NETWORK-INTERFACES]" -ForegroundColor DarkYellow
        }
    }
}

# Final Summary
Write-Host "`n" + "="*80 -ForegroundColor Magenta
Write-Host "FINAL SUMMARY" -ForegroundColor Magenta
Write-Host "="*80 -ForegroundColor Magenta
Write-Host "Total Security Groups with no EC2 instances: $($unusedSecurityGroups.Count)" -ForegroundColor Yellow
Write-Host "  ├─ Completely unused (safe to delete): $($sgCompletelyUnused.Count)" -ForegroundColor Red
Write-Host "  └─ Attached to network interfaces (review needed): $($sgWithNetworkInterfaces.Count)" -ForegroundColor Yellow

if ($sgCompletelyUnused.Count -gt 0 -or $sgWithNetworkInterfaces.Count -gt 0) {
    Write-Host "`nBreakdown by region:" -ForegroundColor Cyan
    foreach ($region in $Regions) {
        $completelyUnusedInRegion = ($sgCompletelyUnused | Where-Object { $_.Region -eq $region }).Count
        $withNIInRegion = ($sgWithNetworkInterfaces | Where-Object { $_.Region -eq $region }).Count
        if ($completelyUnusedInRegion -gt 0 -or $withNIInRegion -gt 0) {
            Write-Host "  $region`: $completelyUnusedInRegion completely unused, $withNIInRegion with network interfaces" -ForegroundColor White
        }
    }
    
    # Combined list with clear labels
    Write-Host "`nCOMBINED LIST (All unused security groups with status):" -ForegroundColor Magenta
    Write-Host "Legend: [SAFE-TO-DELETE] = No instances, no network interfaces" -ForegroundColor DarkRed
    Write-Host "        [HAS-NETWORK-INTERFACES] = No instances, but has network interfaces" -ForegroundColor DarkYellow
    Write-Host ""
    
    # Sort by region then by security group ID for consistent output
    $allUnused = @()
    foreach ($sg in $sgCompletelyUnused) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.SecurityGroupId
            Status = "SAFE-TO-DELETE"
            Color = "DarkRed"
        }
    }
    foreach ($sg in $sgWithNetworkInterfaces) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.SecurityGroupId
            Status = "HAS-NETWORK-INTERFACES"
            Color = "DarkYellow"
        }
    }
    
    $sortedUnused = $allUnused | Sort-Object Region, SecurityGroupId
    foreach ($sg in $sortedUnused) {
        Write-Host "$($sg.Region):$($sg.SecurityGroupId) [$($sg.Status)]" -ForegroundColor $sg.Color
    }
}
