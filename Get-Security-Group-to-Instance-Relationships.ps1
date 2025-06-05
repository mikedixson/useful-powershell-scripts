# PowerShell script to get all security groups and find instances using them
# Requires AWS CLI to be installed and configured

param(
    [string[]]$Regions = @("eu-west-1", "eu-west-2")
)

Write-Host "Starting security group analysis for regions: $($Regions -join ', ')" -ForegroundColor Green

# Track security groups with no instances
$unusedSecurityGroups = @()

foreach ($region in $Regions) {
    Write-Host "`nProcessing region: $region" -ForegroundColor Yellow
    
    try {
        # Get all security groups in the region
        Write-Host "Retrieving security groups from $region..." -ForegroundColor Cyan
        $securityGroups = aws ec2 describe-security-groups --region $region --query "SecurityGroups[*].GroupId" --output text
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to retrieve security groups from region $region"
            continue
        }
        
        if ([string]::IsNullOrWhiteSpace($securityGroups)) {
            Write-Host "No security groups found in region $region" -ForegroundColor Gray
            continue
        }
        
        # Split the security group IDs (AWS CLI returns tab-separated values)
        $sgIds = $securityGroups -split "`t" | Where-Object { $_.Trim() -ne "" }
        
        Write-Host "Found $($sgIds.Count) security groups in $region" -ForegroundColor Green
        
        foreach ($sgId in $sgIds) {
            $sgId = $sgId.Trim()
            if ([string]::IsNullOrWhiteSpace($sgId)) { continue }
            
            Write-Host "`n  Checking instances for security group: $sgId" -ForegroundColor White
            
            try {
                # Get instances using this security group
                $instances = aws ec2 describe-instances --filters "Name=instance.group-id,Values=$sgId" --query "Reservations[*].Instances[*].Tags[?Key=='Name'].Value" --output text --region $region
                
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Failed to query instances for security group $sgId in region $region"
                    continue
                }
                  if ([string]::IsNullOrWhiteSpace($instances)) {
                    Write-Host "    No instances found using security group $sgId" -ForegroundColor Gray
                    # Add to unused security groups list
                    $unusedSecurityGroups += [PSCustomObject]@{
                        Region = $region
                        SecurityGroupId = $sgId
                    }
                } else {
                    # Split instance names (AWS CLI returns tab-separated values)
                    $instanceNames = $instances -split "`t" | Where-Object { $_.Trim() -ne "" }
                    Write-Host "    Found $($instanceNames.Count) instance(s):" -ForegroundColor Green
                    foreach ($instanceName in $instanceNames) {
                        $instanceName = $instanceName.Trim()
                        if (![string]::IsNullOrWhiteSpace($instanceName)) {
                            Write-Host "      - $instanceName" -ForegroundColor Cyan
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

Write-Host "`nSecurity group analysis completed!" -ForegroundColor Green

# Output summary of unused security groups
Write-Host "`n" + "="*60 -ForegroundColor Magenta
Write-Host "SUMMARY: Security Groups with No Instances" -ForegroundColor Magenta
Write-Host "="*60 -ForegroundColor Magenta

if ($unusedSecurityGroups.Count -eq 0) {
    Write-Host "All security groups are currently in use by instances." -ForegroundColor Green
} else {
    Write-Host "Found $($unusedSecurityGroups.Count) security group(s) with no instances:" -ForegroundColor Yellow
    
    # Group by region for better display
    $groupedByRegion = $unusedSecurityGroups | Group-Object -Property Region
    
    foreach ($regionGroup in $groupedByRegion) {
        Write-Host "`nRegion: $($regionGroup.Name)" -ForegroundColor Cyan
        foreach ($sg in $regionGroup.Group) {
            Write-Host "  - $($sg.SecurityGroupId)" -ForegroundColor White
        }
    }
    
    Write-Host "`nPlain list for scripting:" -ForegroundColor Gray
    foreach ($sg in $unusedSecurityGroups) {
        Write-Host "$($sg.Region):$($sg.SecurityGroupId)"
    }
}
