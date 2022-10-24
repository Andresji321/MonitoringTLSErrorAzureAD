<#
.SYNOPSIS
  This script track all autentication logs for specific errorCode 
.DESCRIPTION
  This script track all autentication logs for specific errorCode, by default error code tracked is 1002016 error Code related with TLS deprecation. You can specify path for csv report, hours ago for tracking and tenant id if neccesary

  TenantId: Optional parameter for specify tenant for extract audit logs
  Hours: Hours ago for track log events, by default 1 Hour
  ReportPath: The path to the local filesystem for export of the CSV file.
  ErrorCode: Error code for track de error, by default 1002016 error Code related with TLS deprecation
.PARAMETER TenantId
  Optional parameter for specify tenant for extract audit logs

.PARAMETER Hours
  Hours ago for track log events, by default 1 Hour

.PARAMETER ReportPath
  ReportPath: The path to the local filesystem for export of the CSV file.

.PARAMETER ErrorCode
  ErrorCode: Error code for track de error, by default 1002016 error Code related with TLS deprecation
 
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  CSV files for SignInsInteractive, signInsNonInteractive and signInsWorkloadIdentities. Out Grid View For login Details and count of login event for each User
.NOTES
  Version:        1.0
  Author:         Pablo Andres Jimenez
  Creation Date:  22/10/2022
  Purpose/Change: Initial script development
  Repository: https://github.com/Andresji321/MonitoringTLSErrorAzureAD
.EXAMPLE
  Get-UserWithTLSErrorReport.ps1
  Get  login events with defaul parameters
.EXAMPLE
  Get-UserWithTLSErrorReport.ps1 -Hour 24
  Get login events for last day
.EXAMPLE
  Get-UserWithTLSErrorReport.ps1 -Hour 24 -ReportPath C:\Temp\
  Get login events for last day and put CSV file in C:\Temp\ Folder
#>

#requires -version 4


#---------------------------------------------------------[Script Parameters]------------------------------------------------------
Param (
    [string] $TenantId = "", # Add tenant ID from Azure Active Directory page on portal.
    [int16] $Hours = 1, # Will filter the log for $agoHours from the current date and time.
    [string] $ReportPath = "./",  # The path to the local filesystem for export of the CSV file.
    $errorCode = 1002016 #Error code for track de error, by default 1002016 error Code related with TLS deprecation
)


#---------------------------------------------------------[Initialisations]--------------------------------------------------------
if ($TenantId -eq "") {
    Connect-MgGraph -Scopes "AuditLog.Read.All"
} else {
    Connect-MgGraph -Scopes "AuditLog.Read.All" -TenantId $TenantId
}
   # Or use Directory.Read.All.
Select-MgProfile "beta"  # Low TLS is available in Microsoft Graph preview endpoint.

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$startDate = ((Get-Date).ToUniversalTime().AddHours(-($Hours))).ToString('yyyy-MM-ddTHH:mm:ssZ')  # Get filter start date.
 
#Arrays Definitions 
$TopSignInsInteractiveResult = @()
$TopsignInsNonInteractiveResult = @()
$TopsignInsWorkloadIdentitiesResult = @()

# Define the filtering strings for interactive and non-interactive sign-ins.
$procDetailFunction = "x: x/key eq 'legacy tls (tls 1.0, 1.1, 3des)' and x/value eq '1'"
$clauses = (
    "createdDateTime ge $startDate",    
    "signInEventTypes/any(t: t eq 'nonInteractiveUser')",
    "signInEventTypes/any(t: t eq 'servicePrincipal')",
    "(authenticationProcessingDetails/any($procDetailFunction))"
)

$columnList = @{  # Enumerate the list of properties to be exported to the CSV files.
    Property =  "CorrelationId", 
                "createdDateTime", 
                @{Name = 'HoraLocal'; Expression = {$_.createdDateTime.AddHours(-5)}},
                "userPrincipalName",
                "UserDisplayName",
                @{Name = 'Dominio'; Expression = {$_.userPrincipalName.Split("@")[1]}},
                @{Name = 'DeviceName'; Expression = {$_.DeviceDetail.DisplayName}},
                @{Name = 'OperatingSystem'; Expression = {$_.DeviceDetail.OperatingSystem}},
                @{Name = 'Browser'; Expression = {$_.DeviceDetail.Browser}},
                @{Name = 'TrustType'; Expression = {$_.DeviceDetail.TrustType}},
                @{Name = 'Location'; Expression = {$_.Location.City}},
                "IPAddress",                               
                "AppDisplayName",
                "ResourceDisplayName",
                "userId", 
                "AppId",  
                @{Name = 'Error'; Expression = {$_.Status.ErrorCode}},
                @{Name = 'FailureReason'; Expression = {$_.Status.FailureReason}},                 
                "isInteractive",                 
                "ResourceId", 
                "UserAgent"
}

$columnListWorkloadId = @{ #Enumerate the list of properties for workload identities to be exported to the CSV files.
    Property =  "CorrelationId",
                "createdDateTime", 
                @{Name = 'HoraLocal'; Expression = {$_.createdDateTime.AddHours(-5)}},                
                @{Name = 'Location'; Expression = {$_.Location.City}},
                "IPAddress",                               
                "AppDisplayName",
                "ResourceDisplayName", 
                "AppId",  
                @{Name = 'Error'; Expression = {$_.Status.ErrorCode}},
                @{Name = 'FailureReason'; Expression = {$_.Status.FailureReason}},                 
                "isInteractive",                 
                "ResourceId",
                "ServicePrincipalId", 
                "ServicePrincipalName"
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Get the interactive and non-interactive sign-ins based on filtering clauses.
$signInsInteractive = Get-MgAuditLogSignIn -Filter ($clauses[0,3] -Join " and ") -All
$signInsNonInteractive = Get-MgAuditLogSignIn -Filter ($clauses[0,1,3] -Join " and ") -All
$signInsWorkloadIdentities = Get-MgAuditLogSignIn -Filter ($clauses[0,2,3] -Join " and ") -All



$signInsInteractiveResult = $signInsInteractive | ForEach-Object {
    foreach ($authDetail in $_.Status)
    {
        if ($authDetail.ErrorCode -eq $errorCode)
        {
            $_ | Select-Object @columnList
        }
    }
} 

$signInsNonInteractiveResult = $signInsNonInteractive | ForEach-Object {
    foreach ($authDetail in $_.Status)
    {
        if ($authDetail.ErrorCode -eq $errorCode)
        {
            $_ | Select-Object @columnList
        }
    }
} 

$signInsWorkloadIdentitiesResult = $signInsWorkloadIdentities | ForEach-Object {
    foreach ($authDetail in $_.Status)
    {
        if ($authDetail.ErrorCode -eq $errorCode)
        {
            $_ | Select-Object @columnListWorkloadId
        }
    }
} 


foreach ($user in ($signInsInteractiveResult | Sort-Object -Unique UserDisplayName).UserPrincipalName)
{
    
    $TopSignInsInteractiveResult += New-Object -TypeName psobject -Property @{
        UsuarioUPN = $user
        PeticionesLegacy = ($signInsInteractiveResult | Where-Object {$_.UserPrincipalName -eq $user}).Count
        Type = "Interactive"
    }
    
}

foreach ($user in ($signInsNonInteractiveResult | Sort-Object -Unique UserDisplayName).UserPrincipalName)
{
    
    $TopsignInsNonInteractiveResult += New-Object -TypeName psobject -Property @{
        UsuarioUPN = $user
        PeticionesLegacy = ($signInsNonInteractiveResult | Where-Object {$_.UserPrincipalName -eq $user}).Count
        Type = "NonInteractive"
    }
    
}

foreach ($user in ($signInsWorkloadIdentitiesResult | Sort-Object -Unique UserDisplayName).UserPrincipalName)
{
    
    $TopsignInsWorkloadIdentitiesResult += New-Object -TypeName psobject -Property @{
        UsuarioUPN = $user
        PeticionesLegacy = ($signInsWorkloadIdentitiesResult | Where-Object {$_.UserPrincipalName -eq $user}).Count
    }
    
}

$signInsInteractiveResult | Export-Csv -Path ($ReportPath +"Interactive_lowTls_$tId.csv") -Delimiter "," -NoTypeInformation -Append
$signInsNonInteractiveResult | Export-Csv -Path ($ReportPath +"NonInteractive_lowTls_$tId.csv") -Delimiter "," -NoTypeInformation -Append
$signInsWorkloadIdentitiesResult | Export-Csv -Path ($ReportPath +"WorkloadIdentities_lowTls_$tId.csv")  -Delimiter "," -NoTypeInformation -Append

$TopSignInsInteractiveResult | Sort-Object PeticionesLegacy -Descending | Out-GridView -Title "Conteo de conexiones con uso de TLS obsoleto Interactivo" 
$TopsignInsNonInteractiveResult | Sort-Object PeticionesLegacy -Descending | Out-GridView -Title "Conteo de conexiones con uso de TLS obsoleto " 
$TopsignInsWorkloadIdentitiesResult | Sort-Object PeticionesLegacy -Descending | Out-GridView -Title "Conteo de conexiones con uso de TLS obsoleto WorkLoad"

$signInsInteractiveResult | Out-GridView -Title "Conexiones con uso de TLS obsoleto Interactivo" 
$signInsNonInteractiveResult | Out-GridView -Title "Conexiones con uso de TLS obsoleto No Interactivo" 
$signInsWorkloadIdentitiesResult | Out-GridView -Title "Conexiones con uso de TLS obsoleto WorkLoad"