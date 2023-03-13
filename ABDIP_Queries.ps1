    $art = @'
		               _,--._
	               __/ <a a\__
	            .-"\; \,__/\ \";"-.
	           /     )__"/  \__\(__ \
	         /   __/  o)_ \ / _(o  \_
	        /____\(   /   \/   \)____\
	                \_/^\/^\/^\/^\/^\/^\/
		 ||||
		_||||_
        ____,--'\_\/_/`--..__
            /    /<a     \\     \   \
            (    /   \    / \    \   )
             \__/     \__/   \__/
'@


Write-Host $art

$apiKey = Read-Host "Enter your AbuseIPDB API key"

# Define a function to query the AbuseIPDB API
function Query-AbuseIPDB($ip) {
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"

    # Create a new HTTP request with the API key in the headers
    $request = Invoke-WebRequest -Uri $url -Headers @{Key = $apiKey}

    # Convert the JSON response to a PowerShell object
    $response = ConvertFrom-Json $request.Content

    # Check if the address is listed in the API response
    if ($response.data.abuseConfidenceScore -gt 0) {
        # Extract the domain name and country code from the API response
        $domain = $response.data.domain
        $countryCode = $response.data.countryCode
            
        # Use the country code to get the country name from the API
        $countryUrl = "https://restcountries.com/v2/alpha/$countryCode"
        $countryRequest = Invoke-WebRequest -Uri $countryUrl
        $countryResponse = ConvertFrom-Json $countryRequest.Content
        $country = $countryResponse.name

        # Print a warning message to the user
        Write-Host "-------------------------------------------------------------------------------------------------------------------"
        Write-Host "Warning: $ip ($domain, $country) is listed on the AbuseIPDB with a score of $($response.data.abuseConfidenceScore)"
    }
    else {
        Write-Host "-----------------------------------------------"
        Write-Host "$ip is not listed on the AbuseIPDB"
    }
}
do {
    Write-Host "-------------------------------------------------------------------------------------------------------------------"
    Write-Host "AbuseIPDB Lookup Menu"
    Write-Host "1. Query a single IP"
    Write-Host "2. Query multiple IPs"
    Write-Host "3. Query netstat -ano Foreign Address Only"
    Write-Host "4. Exit"
    $choice = Read-Host "Enter your choice (1, 2, 3, or 4)"

    switch ($choice) {
        1 {
            $ipAddress = Read-Host "Enter the IP address to check"
            Query-AbuseIPDB $ipAddress
        }
        2 {
            $ipList = Read-Host "Enter a comma-separated list of IP addresses to check"
            $ips = $ipList.Split(",").Trim()
            foreach ($ip in $ips) {
                Query-AbuseIPDB $ip
            }
        }
        3 {
            # Run the netstat command to get a list of active network connections
            $netstatOutput = netstat -ano

            # Extract the IP addresses from the netstat output using a regular expression
            $ips = [regex]::Matches($netstatOutput, "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").Value | Sort-Object -Unique

            # Filter out private IP addresses
            $publicIps = @()
            foreach ($ip in $ips) {
                $ipBytes = [IPAddress]::Parse($ip).GetAddressBytes()
                if ($ipBytes[0] -ne 10 -and ($ipBytes[0] -ne 172 -or $ipBytes[1] -lt 16 -or $ipBytes[1] -gt 31) -and ($ipBytes[0] -ne 192 -or $ipBytes[1] -ne 168)) {
                    $publicIps += $ip
                }
            }
            foreach ($ip in $publicIps) {
                Query-AbuseIPDB $ip
            }
        }
        4 {
            break
        }
        default {
            Write-Host "Invalid choice. Please enter a valid option (1, 2, 3, or 4)."
        }
    }
} while ($choice -ne '4')
