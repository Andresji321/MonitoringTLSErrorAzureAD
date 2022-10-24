# MonitoringTLSErrorAzureAD
Powershell Script for monitoring related errors to TLS 1.0 and TLS 1.1 deprecation.


##.SYNOPSIS
  This script track all autentication logs for specific errorCode 
##.DESCRIPTION
  This script track all autentication logs for specific errorCode, by default error code tracked is 1002016 error Code related with TLS deprecation. You can specify path for csv report, hours ago for tracking and tenant id if neccesary
##.PARAMETER <Parameter_Name>
  TenantId: Optional parameter for specify tenant for extract audit logs
  Hours: Hours ago for track log events, by default 1 Hour
  ReportPath: The path to the local filesystem for export of the CSV file.
  ErrorCode: Error code for track de error, by default 1002016 error Code related with TLS deprecation
##.INPUTS
  <Inputs if any, otherwise state None>
##.OUTPUTS
  CSV files for SignInsInteractive, signInsNonInteractive and signInsWorkloadIdentities. Out Grid View For login Details and count of login event for each User
##.NOTES
  Version:        1.0
  Author:         Pablo Andres Jimenez
  Creation Date:  22/10/2022
  Purpose/Change: Initial script development
  Repository: https://github.com/Andresji321/MonitoringTLSErrorAzureAD
##.EXAMPLE
  Get-UserWithTLSErrorReport.ps1
  Get  login events with defaul parameters
##.EXAMPLE
  Get-UserWithTLSErrorReport.ps1 -Hour 24
  Get login events for last day
##.EXAMPLE
  Get-UserWithTLSErrorReport.ps1 -Hour 24 -ReportPath C:\Temp\
  Get login events for last day and put CSV file in C:\Temp\ Folder
