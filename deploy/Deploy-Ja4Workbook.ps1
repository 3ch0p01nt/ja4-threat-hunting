<#
.SYNOPSIS
  Deploys the JA4/JA4S Threat-Hunting workbook to a Microsoft Sentinel workspace.
  Works in Azure Government (IL5) and Azure Commercial.

.EXAMPLE
  # Azure Government (IL5), interactive login:
  .\Deploy-Ja4Workbook.ps1 -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>" -Login

.EXAMPLE
  # Preview only (no changes):
  .\Deploy-Ja4Workbook.ps1 -WorkspaceResourceId "<id>" -WhatIf
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$WorkspaceResourceId,
  [string]$DisplayName = 'JA4/JA4S Threat Hunting',
  [string]$Location,
  [ValidateSet('AzureUSGovernment', 'AzureCloud')][string]$Cloud = 'AzureUSGovernment',
  [string]$TemplateFile = (Join-Path $PSScriptRoot 'azuredeploy.json'),
  [switch]$Login,
  [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'

if ($WorkspaceResourceId -notmatch '/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft.OperationalInsights/workspaces/') {
  throw "WorkspaceResourceId is not a valid Log Analytics workspace ARM ID."
}
$sub = $Matches.sub; $rg = $Matches.rg
Write-Host "Cloud=$Cloud  Subscription=$sub  ResourceGroup=$rg"

az cloud set --name $Cloud | Out-Null
if ($Login) { az login | Out-Null }
az account set --subscription $sub | Out-Null
if (-not $Location) { $Location = az group show -n $rg --query location -o tsv }

$pars = @("workspaceResourceId=$WorkspaceResourceId", "workbookDisplayName=$DisplayName", "location=$Location")

if ($WhatIf) {
  az deployment group what-if -g $rg --template-file $TemplateFile --parameters $pars
}
else {
  $id = az deployment group create -g $rg --name 'ja4-workbook' --template-file $TemplateFile --parameters $pars `
        --query 'properties.outputs.workbookResourceId.value' -o tsv
  Write-Host "Deployed workbook: $id"
  Write-Host "Open: Microsoft Sentinel > $rg workspace > Workbooks > My workbooks > '$DisplayName'"
}
