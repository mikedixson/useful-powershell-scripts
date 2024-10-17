param (
    [string]$serviceName
)
# Parse the input arguments to get the fail count and service name


## To run this script
# powershell.exe Windows_Service_Squadcast_Alert.ps1 -serviceName "ExampleService" /fail=3
# The above command will send an alert to Squadcast for the service "ExampleService" that has failed 3 times.
# You can check the Append fail count to the end of the command line option or hard code as desired.

# Define the webhook URL
$webhookUrl = ""


# Extract the fail count value from the automatic argument
$failCountValue = $args[0] -replace '/fail=', ''

# Retrieve useful data from the service failure/event log
$failureTime = Get-Date

# Construct the event ID based on the service name
$eventId = "event_" + $serviceName

# Construct the payload for the alert
$payload = @{
    message     = "Service $serviceName has failed $failCountValue times."
    description = "Service $serviceName failed at $failureTime. Fail count: $failCountValue."
    status      = "trigger"
    event_id    = $eventId
} | ConvertTo-Json

# Send the payload to the Squadcast webhook using an HTTP POST request
Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType "application/json"
