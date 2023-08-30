
<#
--------------------------------------------------------------------
MIT License
Copyright (c) 2023 Jacob Scott

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
--------------------------------------------------------------------
Description:
This script is a way to quickly delete devices from Autopilot Devices. 
Once authenticated, enter the serial number to be searched for
If found, it will check if the device is present in Intune.
If so, user is given the option to retire/delete it first.
Device is then removed from Intune once confirmation is provided. 

#>
[CmdletBinding()]

param
(
    [Parameter(Mandatory=$false)]
    [string]$sn
)

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Get-APDevice(){

<#
.SYNOPSIS
This function is used to find if the serial number appears in autopilot devices
.EXAMPLE
Get-APDevice -sn "abc123"
Returns autopilot device with serial number abc123
.NOTES
NAME: Get-APDevice
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$false)]
    [string]$sn
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/windowsAutopilotDeviceIdentities"

    try {

        if($sn -ne ""){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'serialNumber').contains("$sn") }

        }

        else {

        Write-Host "Specify serial number using -sn" -f Red
        break

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Delete-ManagedDevice(){

<#
.SYNOPSIS
This function is used to retire/delete an intune managed device
.EXAMPLE
Delete-ManagedDevice $intuneDeviceId guid
.NOTES
NAME: Delete-ManagedDevice
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$false)]
    $intuneDeviceId
)

Write-verbose "Intunedeviceid to remove: $intuneDeviceId"

$graphApiVersion = "Beta"
$delete_resource = "/deviceManagement/managedDevices/$intuneDeviceId/retire"

    try {

        if($intuneDeviceId -ne ""){
            $confirmation = Read-Host "Are you sure you want to retire Intune Device ID $intuneDeviceId ?"
            if ($confirmation -eq 'y'){
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($delete_resource)"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post).Value
            }
            else {
                Write-Host "Not deleting IntuneDeviceID: $intuneDeviceId" -f Red
                $confirmation = Read-Host "Did you still want to remove the device from Autopilot?"
                if ($confirmation -eq 'y'){
                    #do nothing to continue
                }
                else{
                    Write-Host "Exiting without removing serial number $sn from Autopilot"
                    break
                }   
            }
        }

        else {

            Write-Host "IntuneDeviceID missing" -f Red
            break
        }
    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################
####################################################

Function Delete-APDevice(){

<#
.SYNOPSIS
This function is used to delete a device from Autopilot > Devices
.EXAMPLE
Delete-APDevice $apID guid
.NOTES
NAME: Delete-APDevice
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$false)]
    $apID
)

Write-verbose "APID to remove: $apID"

$graphApiVersion = "Beta"
$deleteAP_resource = "deviceManagement/windowsAutopilotDeviceIdentities/$apID"

    try {

        if($apID -ne ""){
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($deleteAP_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete).Value
        }
        else {

            Write-Host "APID missing" -f Red
            break
        }
    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################


#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

$apdevice = Get-APDevice -sn $sn
if($apdevice -eq "" -or $apdevice -eq $null){
    Write-Host "Serial number $sn not found. Exiting" -f Red
    break
}
else {
    write-verbose '----'
    write-verbose $apdevice
    write-verbose '----'
    Write-verbose 'device returned'
    $id = $apdevice.id
    write-verbose "id:  $id"
    $managedDeviceId= $apdevice.managedDeviceId
    write-verbose "intunedeviceid: $managedDeviceId"
}

if ($managedDeviceId -eq "00000000-0000-0000-0000-000000000000") {
    Write-Host "Device not in Intune, ready to delete"
}
else {
    Delete-ManagedDevice -intuneDeviceId $managedDeviceId
}

$confirmation = Read-Host "Are you sure you want to remove serial number $sn from Autopilot?"
if ($confirmation -eq 'y'){
    Delete-APDevice -apID $id
}
else {
    Write-Host "Exiting without removing $sn from Autopilot"
    break
}
