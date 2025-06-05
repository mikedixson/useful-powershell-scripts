# PowerShell script to get all security groups and find instances using them
# Optimized version with reduced API calls
# Requires AWS CLI to be installed and configured

param(
    [string[]]$Regions = @("eu-west-1", "eu-west-2"),
    [switch]$Verbose
)

Write-Host "Starting optimized security group analysis for regions: $($Regions -join ', ')" -ForegroundColor Green

# Track security groups with no instances
$unusedSecurityGroups = @()
$sgWithNetworkInterfaces = @()
$sgCompletelyUnused = @()
$sgReferencedByOtherSGs = @()
$sgDefaultGroups = @()

# For progress tracking
$totalRegions = $Regions.Count
$processedRegions = 0

foreach ($region in $Regions) {
    $processedRegions++
    
    if ($Verbose) {
        Write-Host "`n=== Region: $region ($processedRegions/$totalRegions) ===" -ForegroundColor Yellow
    } else {
        Write-Host "`nProcessing region $region ($processedRegions/$totalRegions)..." -ForegroundColor Yellow
    }
    
    try {
        # OPTIMIZATION: Fetch all data for the region in bulk to minimize API calls
        Write-Host "Fetching security groups data for $region..." -ForegroundColor Cyan
        $allSecurityGroups = aws ec2 describe-security-groups --region $region --output json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error fetching security groups for region $region" -ForegroundColor Red
            continue
        }
        
        $securityGroupsData = $allSecurityGroups | ConvertFrom-Json
        if (-not $securityGroupsData.SecurityGroups -or $securityGroupsData.SecurityGroups.Count -eq 0) {
            Write-Host "No security groups found in region $region" -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Fetching instances data for $region..." -ForegroundColor Cyan
        $allInstances = aws ec2 describe-instances --region $region --output json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error fetching instances for region $region" -ForegroundColor Red
            continue
        }
        
        $instancesData = $allInstances | ConvertFrom-Json
        
        Write-Host "Fetching network interfaces data for $region..." -ForegroundColor Cyan
        $allNetworkInterfaces = aws ec2 describe-network-interfaces --region $region --output json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error fetching network interfaces for region $region" -ForegroundColor Red
            continue
        }
        
        $networkInterfacesData = $allNetworkInterfaces | ConvertFrom-Json
          # OPTIMIZATION: Build lookup tables for efficient searching instead of individual API calls
        Write-Host "Building lookup tables for efficient analysis..." -ForegroundColor Cyan
        
        # Build default security groups lookup
        $defaultSecurityGroups = @{}
        foreach ($sg in $securityGroupsData.SecurityGroups) {
            if ($sg.GroupName -eq "default") {
                $defaultSecurityGroups[$sg.GroupId] = @{
                    GroupId = $sg.GroupId
                    GroupName = $sg.GroupName
                    VpcId = $sg.VpcId
                    IsDefault = $true
                }
            }
        }
        
        # Build instance security groups lookup
        $instanceSecurityGroups = @{}
        foreach ($reservation in $instancesData.Reservations) {
            foreach ($instance in $reservation.Instances) {
                foreach ($sg in $instance.SecurityGroups) {
                    if (-not $instanceSecurityGroups.ContainsKey($sg.GroupId)) {
                        $instanceSecurityGroups[$sg.GroupId] = @()
                    }
                    $instanceSecurityGroups[$sg.GroupId] += @{
                        InstanceId = $instance.InstanceId
                        InstanceName = ($instance.Tags | Where-Object { $_.Key -eq "Name" }).Value
                        State = $instance.State.Name
                    }
                }
            }
        }
        
        # Build network interface security groups lookup
        $networkInterfaceSecurityGroups = @{}
        foreach ($ni in $networkInterfacesData.NetworkInterfaces) {
            foreach ($sg in $ni.Groups) {
                if (-not $networkInterfaceSecurityGroups.ContainsKey($sg.GroupId)) {
                    $networkInterfaceSecurityGroups[$sg.GroupId] = @()
                }
                $networkInterfaceSecurityGroups[$sg.GroupId] += @{
                    NetworkInterfaceId = $ni.NetworkInterfaceId
                    Description = $ni.Description
                    Status = $ni.Status
                    VpcId = $ni.VpcId
                }
            }
        }
        
        # Build security group references lookup
        $securityGroupReferences = @{}
        foreach ($sg in $securityGroupsData.SecurityGroups) {
            # Check ingress rules
            foreach ($rule in $sg.IpPermissions) {
                foreach ($userIdGroupPair in $rule.UserIdGroupPairs) {
                    if ($userIdGroupPair.GroupId) {
                        if (-not $securityGroupReferences.ContainsKey($userIdGroupPair.GroupId)) {
                            $securityGroupReferences[$userIdGroupPair.GroupId] = @()
                        }
                        $securityGroupReferences[$userIdGroupPair.GroupId] += @{
                            ReferencedBy = $sg.GroupId
                            ReferencedByName = $sg.GroupName
                            RuleType = "Ingress"
                            Protocol = $rule.IpProtocol
                            FromPort = $rule.FromPort
                            ToPort = $rule.ToPort
                        }
                    }
                }
            }
            
            # Check egress rules
            foreach ($rule in $sg.IpPermissionsEgress) {
                foreach ($userIdGroupPair in $rule.UserIdGroupPairs) {
                    if ($userIdGroupPair.GroupId) {
                        if (-not $securityGroupReferences.ContainsKey($userIdGroupPair.GroupId)) {
                            $securityGroupReferences[$userIdGroupPair.GroupId] = @()
                        }
                        $securityGroupReferences[$userIdGroupPair.GroupId] += @{
                            ReferencedBy = $sg.GroupId
                            ReferencedByName = $sg.GroupName
                            RuleType = "Egress"
                            Protocol = $rule.IpProtocol
                            FromPort = $rule.FromPort
                            ToPort = $rule.ToPort
                        }
                    }
                }
            }
        }
        
        $regionSgCount = $securityGroupsData.SecurityGroups.Count
        $processedInRegion = 0
        
        Write-Host "Analyzing $regionSgCount security groups in $region..." -ForegroundColor Green
        
        # OPTIMIZATION: Process all security groups using pre-built lookup tables
        foreach ($sg in $securityGroupsData.SecurityGroups) {
            $processedInRegion++
            
            if (-not $Verbose) {
                $overallProgress = [math]::Round((($processedRegions - 1) * 100 + ($processedInRegion / $regionSgCount * 100)) / $totalRegions)
                Write-Progress -Activity "Analyzing Security Groups" -Status "Region: $region - Processing $($sg.GroupId) ($processedInRegion/$regionSgCount)" -PercentComplete $overallProgress
            }
            
            $groupId = $sg.GroupId
            $groupName = $sg.GroupName
            $description = $sg.Description
            $vpcId = $sg.VpcId
            
            # Check if this security group is attached to any instances using lookup table
            $attachedInstances = $instanceSecurityGroups[$groupId]
            
            if ($Verbose) {
                Write-Host "`nSecurity Group: $groupName ($groupId)" -ForegroundColor Cyan
                Write-Host "Description: $description" -ForegroundColor Gray
                Write-Host "VPC: $vpcId" -ForegroundColor Gray
            }
            
            if ($attachedInstances) {
                if ($Verbose) {
                    Write-Host "Attached to the following instances:" -ForegroundColor Green
                    foreach ($instance in $attachedInstances) {
                        $instanceName = if ($instance.InstanceName) { " ($($instance.InstanceName))" } else { "" }
                        Write-Host "  - Instance ID: $($instance.InstanceId)$instanceName - State: $($instance.State)" -ForegroundColor White
                    }
                }            } else {
                # Check if this is a default security group
                $isDefaultSG = $defaultSecurityGroups.ContainsKey($groupId)
                
                # Check for network interfaces using lookup table
                $attachedNetworkInterfaces = $networkInterfaceSecurityGroups[$groupId]
                
                # Check for security group references using lookup table
                $referencedBy = $securityGroupReferences[$groupId]
                
                if ($isDefaultSG) {
                    # This is a default security group - should not be deleted
                    $unusedSecurityGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        ReferencedBy = $referencedBy
                        Category = "DefaultSecurityGroup"
                        IsDefault = $true
                    }
                    $sgDefaultGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        ReferencedBy = $referencedBy
                        IsDefault = $true
                    }
                    
                    if ($Verbose) {
                        Write-Host "[DEFAULT-SECURITY-GROUP] This is a default VPC security group - should NOT be deleted" -ForegroundColor Blue
                    }
                } elseif ($attachedNetworkInterfaces -and $referencedBy) {
                    # Has both network interfaces and references
                    $unusedSecurityGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        ReferencedBy = $referencedBy
                        Category = "HasNetworkInterfacesAndReferences"
                    }
                    $sgWithNetworkInterfaces += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        ReferencedBy = $referencedBy
                    }
                    $sgReferencedByOtherSGs += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        ReferencedBy = $referencedBy
                    }
                } elseif ($attachedNetworkInterfaces) {
                    # Has network interfaces only
                    $unusedSecurityGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                        Category = "HasNetworkInterfaces"
                    }
                    $sgWithNetworkInterfaces += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        NetworkInterfaces = $attachedNetworkInterfaces
                    }
                    
                    if ($Verbose) {
                        Write-Host "[HAS-NETWORK-INTERFACES] No instances found, but attached to network interfaces:" -ForegroundColor Yellow
                        foreach ($ni in $attachedNetworkInterfaces) {
                            Write-Host "  - Network Interface: $($ni.NetworkInterfaceId) - Status: $($ni.Status) - Description: $($ni.Description)" -ForegroundColor White
                        }
                    }
                } elseif ($referencedBy) {
                    # Referenced by other security groups only
                    $unusedSecurityGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        ReferencedBy = $referencedBy
                        Category = "ReferencedByOtherSGs"
                    }
                    $sgReferencedByOtherSGs += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        ReferencedBy = $referencedBy
                    }
                    
                    if ($Verbose) {
                        Write-Host "[REFERENCED-BY-OTHER-SGs] No instances found, but referenced by other security groups:" -ForegroundColor Magenta
                        foreach ($ref in $referencedBy) {
                            Write-Host "  - Referenced by: $($ref.ReferencedByName) ($($ref.ReferencedBy)) - $($ref.RuleType) - Protocol: $($ref.Protocol)" -ForegroundColor White
                        }
                    }
                } else {
                    # Completely unused
                    $unusedSecurityGroups += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                        Category = "CompletelyUnused"
                    }
                    $sgCompletelyUnused += @{
                        Region = $region
                        GroupId = $groupId
                        GroupName = $groupName
                        Description = $description
                        VpcId = $vpcId
                    }
                    
                    if ($Verbose) {
                        Write-Host "[SAFE-TO-DELETE] No instances, network interfaces, or references found" -ForegroundColor Red
                    }
                }
            }
        }
        
        if (-not $Verbose) {
            Write-Progress -Activity "Analyzing Security Groups" -Completed
        }
        
        Write-Host "Completed analysis for region $region" -ForegroundColor Green
        
    } catch {
        Write-Error "Error processing region $region`: $($_.Exception.Message)"
    }
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
        Write-Host "All security groups are currently in use by EC2 instances." -ForegroundColor Green    } else {
        Write-Host "Found $($unusedSecurityGroups.Count) security group(s) with no EC2 instances attached." -ForegroundColor Yellow
    }

    # Output default security groups first (most important warning)
    Write-Host "`n" + "-"*80 -ForegroundColor Blue
    Write-Host "Default VPC Security Groups (NEVER DELETE - AWS Managed)" -ForegroundColor Blue
    Write-Host "-"*80 -ForegroundColor Blue

    if ($sgDefaultGroups.Count -eq 0) {
        Write-Host "No default security groups found without instances." -ForegroundColor Green
    } else {
        Write-Host "Found $($sgDefaultGroups.Count) default security group(s) with no EC2 instances:" -ForegroundColor Blue
        Write-Host "WARNING: These are AWS-managed default security groups and should NEVER be deleted!" -ForegroundColor Red
        
        # Group by region for better display
        $groupedDefaultSGs = $sgDefaultGroups | Group-Object -Property Region
        
        foreach ($regionGroup in $groupedDefaultSGs) {
            Write-Host "`nRegion: $($regionGroup.Name)" -ForegroundColor Cyan
            foreach ($sg in $regionGroup.Group) {
                Write-Host "  - $($sg.GroupId) ($($sg.GroupName)) - VPC: $($sg.VpcId)" -ForegroundColor White
            }
        }
        
        Write-Host "`nPlain list for scripting (default security groups - DO NOT DELETE):" -ForegroundColor Gray
        foreach ($sg in $sgDefaultGroups) {
            Write-Host "$($sg.Region):$($sg.GroupId) [DEFAULT-VPC-SG-DO-NOT-DELETE]" -ForegroundColor Blue
        }
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
                Write-Host "  - $($sg.GroupId) ($($sg.GroupName))" -ForegroundColor White
            }
        }
        
        Write-Host "`nPlain list for scripting (completely unused):" -ForegroundColor Gray
        foreach ($sg in $sgCompletelyUnused) {
            Write-Host "$($sg.Region):$($sg.GroupId) [SAFE-TO-DELETE]" -ForegroundColor DarkRed
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
                Write-Host "  - $($sg.GroupId) ($($sg.GroupName))" -ForegroundColor White
            }
        }

        Write-Host "`nPlain list for scripting (with network interfaces):" -ForegroundColor Gray
        foreach ($sg in $sgWithNetworkInterfaces) {
            Write-Host "$($sg.Region):$($sg.GroupId) [HAS-NETWORK-INTERFACES]" -ForegroundColor DarkYellow
        }
    }

    # Output security groups referenced by other security groups
    Write-Host "`n" + "-"*80 -ForegroundColor Yellow
    Write-Host "Security Groups with NO Instances BUT Referenced by Other Security Groups (Review Before Deleting)" -ForegroundColor Yellow
    Write-Host "-"*80 -ForegroundColor Yellow

    if ($sgReferencedByOtherSGs.Count -eq 0) {
        Write-Host "No security groups found that are referenced by other security groups but have no instances." -ForegroundColor Green
    } else {
        Write-Host "Found $($sgReferencedByOtherSGs.Count) security group(s) referenced by other security groups:" -ForegroundColor Yellow
        
        # Group by region for better display
        $groupedReferencedSGs = $sgReferencedByOtherSGs | Group-Object -Property Region
        
        foreach ($regionGroup in $groupedReferencedSGs) {
            Write-Host "`nRegion: $($regionGroup.Name)" -ForegroundColor Cyan
            foreach ($sg in $regionGroup.Group) {
                Write-Host "  - $($sg.GroupId) ($($sg.GroupName))" -ForegroundColor White
            }
        }
        
        Write-Host "`nPlain list for scripting (referenced by other SGs):" -ForegroundColor Gray
        foreach ($sg in $sgReferencedByOtherSGs) {
            Write-Host "$($sg.Region):$($sg.GroupId) [REFERENCED-BY-OTHER-SGs]" -ForegroundColor DarkYellow
        }
    }
}

# Final Summary
Write-Host "`n" + "="*80 -ForegroundColor Magenta
Write-Host "FINAL SUMMARY" -ForegroundColor Magenta
Write-Host "="*80 -ForegroundColor Magenta
Write-Host "Total Security Groups with no EC2 instances: $($unusedSecurityGroups.Count)" -ForegroundColor Yellow
Write-Host "  ├─ Default VPC security groups (NEVER delete): $($sgDefaultGroups.Count)" -ForegroundColor Blue
Write-Host "  ├─ Completely unused (safe to delete): $($sgCompletelyUnused.Count)" -ForegroundColor Red
Write-Host "  ├─ Attached to network interfaces (review needed): $($sgWithNetworkInterfaces.Count)" -ForegroundColor Yellow
Write-Host "  └─ Referenced by other security groups (review needed): $($sgReferencedByOtherSGs.Count)" -ForegroundColor Yellow

if ($sgDefaultGroups.Count -gt 0 -or $sgCompletelyUnused.Count -gt 0 -or $sgWithNetworkInterfaces.Count -gt 0 -or $sgReferencedByOtherSGs.Count -gt 0) {
    Write-Host "`nBreakdown by region:" -ForegroundColor Cyan
    foreach ($region in $Regions) {        $defaultInRegion = ($sgDefaultGroups | Where-Object { $_.Region -eq $region }).Count
        $completelyUnusedInRegion = ($sgCompletelyUnused | Where-Object { $_.Region -eq $region }).Count
        $withNIInRegion = ($sgWithNetworkInterfaces | Where-Object { $_.Region -eq $region }).Count
        $referencedInRegion = ($sgReferencedByOtherSGs | Where-Object { $_.Region -eq $region }).Count
        
        if ($defaultInRegion -gt 0 -or $completelyUnusedInRegion -gt 0 -or $withNIInRegion -gt 0 -or $referencedInRegion -gt 0) {
            Write-Host "  $region`: $defaultInRegion default (never delete), $completelyUnusedInRegion completely unused, $withNIInRegion with network interfaces, $referencedInRegion referenced by other SGs" -ForegroundColor White
        }
    }
    
    # Combined list with clear labels
    Write-Host "`nCOMBINED LIST (All unused security groups with status):" -ForegroundColor Magenta
    Write-Host "Legend: [DEFAULT-VPC-SG-DO-NOT-DELETE] = Default VPC security group - AWS managed" -ForegroundColor Blue
    Write-Host "        [SAFE-TO-DELETE] = No instances, no network interfaces, not referenced" -ForegroundColor DarkRed
    Write-Host "        [HAS-NETWORK-INTERFACES] = No instances, but has network interfaces" -ForegroundColor DarkYellow
    Write-Host "        [REFERENCED-BY-OTHER-SGs] = No instances, but referenced by other security groups" -ForegroundColor DarkYellow
    Write-Host ""
      # Sort by region then by security group ID for consistent output
    $allUnused = @()
    foreach ($sg in $sgDefaultGroups) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.GroupId
            SecurityGroupName = $sg.GroupName
            Status = "DEFAULT-VPC-SG-DO-NOT-DELETE"
            Color = "Blue"
            SortOrder = 1
        }
    }
    foreach ($sg in $sgCompletelyUnused) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.GroupId
            SecurityGroupName = $sg.GroupName
            Status = "SAFE-TO-DELETE"
            Color = "DarkRed"
            SortOrder = 2
        }
    }
    foreach ($sg in $sgWithNetworkInterfaces) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.GroupId
            SecurityGroupName = $sg.GroupName
            Status = "HAS-NETWORK-INTERFACES"
            Color = "DarkYellow"
            SortOrder = 3
        }    }    foreach ($sg in $sgReferencedByOtherSGs) {
        $allUnused += [PSCustomObject]@{
            Region = $sg.Region
            SecurityGroupId = $sg.GroupId
            SecurityGroupName = $sg.GroupName
            Status = "REFERENCED-BY-OTHER-SGs"
            Color = "DarkYellow"
            SortOrder = 4
        }
    }
    
    # Sort by Region, then by State (SortOrder), then by SecurityGroupId
    $sortedUnused = $allUnused | Sort-Object Region, SortOrder, SecurityGroupId
    foreach ($sg in $sortedUnused) {
        Write-Host "$($sg.Region):$($sg.SecurityGroupId) [$($sg.Status)]" -ForegroundColor $sg.Color
    }
}


