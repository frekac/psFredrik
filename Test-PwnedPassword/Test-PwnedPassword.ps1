<#
.Synopsis
   Tests if the supplied password has been previously leaked or breached.
.DESCRIPTION
   The function will check if the password you enter is found at 'Have I been pwned'.
   The database contains aprox 550 million passwords that have been found in breaches.
   The API don't require the whole password hash to be checked but the first five characters in the hash.
   So the complete hash is not sent to the API.
   You can find more information of usage here: https://haveibeenpwned.com/API/v2#APIVersion
.EXAMPLE
   Test-PwnedPassword -Password 'Passw0rd'
#>
function Test-PwnedPassword
{
    [CmdletBinding()]
    Param
    (
        # The Password To Test
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Password,

        # The Api Uri 
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$Uri = "https://api.pwnedpasswords.com/range"
    )
    # First check if Tls12 is enabled, if not, enable it.
    Assert-SecurityProtocol

    # Create the sha object.
    $sha = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider

    # Convert the Password to UTF8 encoded byte
    [byte[]]$data = [System.Text.Encoding]::UTF8.GetBytes($password)

    # SHA-1 Hash the Password
    [byte[]]$hashedBytes = $sha.ComputeHash($data)

    # Convert the integer values in the byte array to Hex-string
    $hashedString = -join ($hashedBytes | % {"{0:X2}" -f $_})

    Write-Verbose "Hash: $hashedString"

    # Get the first 5 characters in the hexString to create the range
    $range = $hashedString.Substring(0,5)

    # Get all the hashed passwords within the range.
    $rangeResult = Invoke-RestMethod -Uri "$Uri/$range"
    $searchList = $rangeResult.Split("`r`n",[System.StringSplitOptions]::RemoveEmptyEntries)

    # Create the search string, all characters except the first five in the range.
    $searchString = $hashedString.Substring(5)

    # Check for the searchString in the searchList
    foreach($s in $searchList) {
        
        if($s -like "$searchString*"){
            # Get the amount of times the password has been found.
            $prevelance = $s.Split(':')[1]
            
            $result = [PSCustomObject]@{"BreachedPassword" = $true;
                                        "TimesFound" = $prevelance
                                       }
        }
    }

    # Create result if there wasn't a match earler
    if(-not $result) {
        $result = [PSCustomObject]@{"BreachedPassword" = $false
                                    "TimesFound" = 0
                                   }
    }
    
    $result
}

function Assert-SecurityProtocol {
    # Get the list of SSL protocols which are enabled.
    $enabledProtocols = [System.Net.ServicePointManager]::SecurityProtocol
    
    if($enabledProtocols -notlike "*Tls12*"){
        
        # Enable TLS 1.2 since it's required by the API
        $enabledProtocols += [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::SecurityProtocol = $enabledProtocols;
    }
}