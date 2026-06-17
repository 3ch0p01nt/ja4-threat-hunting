// ============================================================================
// JA4/JA4S Threat-Hunting Workbook - Bicep deployment
// Cloud-agnostic: deploys to Azure Commercial OR Azure Government (IL5).
// NOTE: the workbook now exceeds Bicep's loadTextContent() 128 KB limit, so the
// serialized content is a PARAMETER here. The "Deploy to Azure" button uses
// deploy/azuredeploy.json (ARM), which embeds the content directly with no size
// limit and is the recommended path. For a bicep deploy, pass the contents of
// workbook-content.json, e.g.:
//   az deployment group create -g <rg> --template-file main.bicep \
//     --parameters workspaceResourceId=<id> serializedData=@workbook-content.json
// ============================================================================

@description('Resource ID of the target Log Analytics / Microsoft Sentinel workspace (becomes the workbook sourceId).')
param workspaceResourceId string

@description('Display name shown under Sentinel > Workbooks.')
param workbookDisplayName string = 'JA4/JA4S Threat Hunting'

@description('Region for the workbook resource. For IL5 use e.g. usgovvirginia or usgovarizona.')
param location string = resourceGroup().location

@description('Deterministic GUID name so repeated deployments update the same workbook in place.')
param workbookId string = guid(resourceGroup().id, workbookDisplayName)

@description('Serialized workbook JSON (contents of workbook-content.json). The Deploy button / azuredeploy.json embeds this automatically.')
param serializedData string

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: serializedData
    version: 'Notebook/1.0'
    sourceId: workspaceResourceId
    category: 'sentinel'
  }
}

output workbookResourceId string = workbook.id
output openInPortalHint string = 'Microsoft Sentinel > (your workspace) > Workbooks > My workbooks > ${workbookDisplayName}'
