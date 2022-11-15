<#
.Synopsis
   Get the content of the encrypted file
.DESCRIPTION
   lists the content of the encrypted file, the source file need to be encrypted by the same user on the same machine.
   The encryption is using the windows DPAPI methods and is using the currentuser scope.
.EXAMPLE
   Get-EncryptedData -FilePath <path to file>
#>
function Get-EncryptedData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if(-not (Test-Path $FilePath)) {
        throw "File to decrypt not found at: $FilePath"
    }

    $encryptedFileContent = Get-Content -Path $FilePath
    $byteContent = [Convert]::FromBase64String($encryptedFileContent)
    $protectionScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    $decryptContent = [System.Security.Cryptography.ProtectedData]::Unprotect($byteContent, $null, $protectionScope)
    $stringContent = [System.Text.Encoding]::UTF8.GetString($decryptContent)

    $stringContent | ConvertFrom-Json
}

<#
.Synopsis
   Set the content of the encrypted file
.DESCRIPTION
   Will take the supplied JSON data and encrypt it at the supplied file location.
   It's using Windows DPAPI in the currentuser scope which mean you can only decrypt it on the same machine using the same user.
   It stores the file in base64 format after encryption.
.EXAMPLE
   Set-EncryptedData -FilePath <path to file> -JsonData <data in json format>
#>
function Set-EncryptedData {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'JsonFile')]
        [string]$JsonFile,

        [Parameter(ParameterSetName = 'JsonData')]
        [string]$JsonData,

        [Parameter(Mandatory = $true)]
        [string]$EncryptedFilePath
    )

    if(($PSCmdlet.ParameterSetName -eq 'JsonFile') -and (-not ([String]::IsNullOrEmpty($JsonFile)))) {
        $contentToEncrypt = Get-Content -Path $JsonFile
    }

    if(($PSCmdlet.ParameterSetName -eq 'JsonData') -and (-not ([String]::IsNullOrEmpty($JsonData)))) {
        $contentToEncrypt = $JsonData
    }

    try{
        $contentToEncrypt | ConvertFrom-Json | Out-Null
    } catch {
        throw "there was an error parsing the data as json"
    }

    [byte[]]$byteContent = [System.Text.Encoding]::UTF8.GetBytes($contentToEncrypt)
    $protectionScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    $encryptContent = [System.Security.Cryptography.ProtectedData]::Protect($byteContent, $null, $protectionScope)
    $b64Content = [Convert]::ToBase64String($encryptContent)

    $b64Content | Out-File -FilePath $EncryptedFilePath -Encoding UTF8
}

<#
.Synopsis
   Update the content of the encrypted file
.DESCRIPTION
   Will use the Get-EncryptedData and Set-EncryptedData functions for retreiving and saving the encrypted information.
   In between this function will add/change or remove a property and value depending on which options are used.
.EXAMPLE
   Update-EncryptedData -FilePath <path to file> -PropertyName <property name>

   Will let you enter the property value, if it's an existing property it will be changed or added if it doesn't exist in the file.
.EXAMPLE
   Update-EncryptedData -FilePath <path to file> -PropertyName <property name> -AutoSetValue

   Will add/set the property value by a randomized string, 20 characters in length.
.EXAMPLE
   Update-EncryptedData -FilePath <path to file> -PropertyName <property name> -DeleteProperty

   Will delete the property from the file.
#>
function Update-EncryptedData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedFilePath,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,
        
        [switch]$DeleteProperty,
        [switch]$AutoSetValue
    )

    if(-not (Test-Path $EncryptedFilePath)) {
        throw "there was no encrypted file to update at: $EncryptedFilePath"
    }

    $decryptedData = Get-EncryptedData -FilePath $EncryptedFilePath

    if($DeleteProperty -and ($decryptedData.psobject.properties.Name -contains $PropertyName)) {
        Remove-PropertyData -EncryptedFilePath $EncryptedFilePath -DataObject $decryptedData -PropertyName $PropertyName
        return "Property deleted"
    }

    if($AutoSetValue) {
        $stringData = New-RandomPassword -PasswordLength 20
    } else {
        $updateData = Read-Host -AsSecureString -Prompt "Enter property value: "
        $stringData = [System.Net.NetworkCredential]::new('', $updateData).Password
    }

    if($decryptedData.psobject.properties.Name -contains $PropertyName) {
        $decryptedData.$PropertyName = $stringData
    } else {
        $decryptedData | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $stringData
    }

    Set-EncryptedData -EncryptedFilePath $EncryptedFilePath -JsonData ($decryptedData | ConvertTo-Json)
}

function Remove-PropertyData {
    param (
        $DataObject,
        [string]$EncryptedFilePath,
        [string]$PropertyName
    )

    $confirmation = Read-Host "Are you sure you want to delete the property $PropertyName (y/n): "
    if($confirmation -eq 'y') {
        $DataObject.psobject.Properties.Remove($PropertyName)
    }

    Set-EncryptedData -EncryptedFilePath $EncryptedFilePath -JsonData ($DataObject | ConvertTo-Json)
}

<#
.Synopsis
   Create a new encrypted file
.DESCRIPTION
   Will create an empty encrypted file that you can the use.
.EXAMPLE
   New-EncryptedFile -EncryptedFilePath <path for saving a new file>
#>
function New-EncryptedFile {
    param (
        [string]$EncryptedFilePath
    )

    Set-EncryptedData -EncryptedFilePath $EncryptedFilePath -JsonData '{}'
}

<#
.Synopsis
   Create a random password
.DESCRIPTION
   Will create a random password you can select wether to use special characters or not.
.EXAMPLE
   New-RandomPassword -PasswordLength <int number> -UseSpecialCharacters
#>
function New-RandomPassword {
    param(
        [int]$PasswordLength,
        [switch]$UseSpecialCharacters
    )

    $lowerCaseChar = 'a'..'z'
    $upperCaseChar = 'A'..'Z'
    $numberChar = '0'..'9'
    $specialChar = '!'..'/'
    $charSetCount = 4

    if($UseSpecialCharacters){
        $charSetCount = 5
    }

    $sb = [System.Text.StringBuilder]::new()

    for ($i = 0; $i -lt $PasswordLength; $i++) {
        $selectCharacterSet = Get-Random -Minimum 1 -Maximum $charSetCount

        switch($selectCharacterSet) {
            1 {$charSet = $lowerCaseChar; break}
            2 {$charSet = $upperCaseChar; break}
            3 {$charSet = $numberChar; break}
            4 {$charSet = $specialChar; break} 
        }

        [void]$sb.Append(($charSet | Get-Random))
    }

    $sb.ToString()
}