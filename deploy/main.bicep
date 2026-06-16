// ============================================================================
// JA4/JA4S Threat-Hunting Workbook - Bicep deployment
// Cloud-agnostic: deploys to Azure Commercial OR Azure Government (IL5).
// The workbook content is loaded verbatim from workbook-content.json at compile
// time (loadTextContent), so there is nothing to escape by hand.
//   az deployment group create -g <rg> --template-file main.bicep \
//       --parameters workspaceResourceId=<workspace-resource-id> location=usgovvirginia
// ============================================================================

@description('Resource ID of the target Log Analytics / Microsoft Sentinel workspace (becomes the workbook sourceId).')
param workspaceResourceId string

@description('Display name shown under Sentinel > Workbooks.')
param workbookDisplayName string = 'JA4/JA4S Threat Hunting'

@description('Region for the workbook resource. For IL5 use e.g. usgovvirginia or usgovarizona.')
param location string = resourceGroup().location

@description('Deterministic GUID name so repeated deployments update the same workbook in place.')
param workbookId string = guid(resourceGroup().id, workbookDisplayName)

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: loadTextContent('workbook-content.json')
    version: 'Notebook/1.0'
    sourceId: workspaceResourceId
    category: 'sentinel'
  }
}

output workbookResourceId string = workbook.id
output openInPortalHint string = 'Microsoft Sentinel > (your workspace) > Workbooks > My workbooks > ${workbookDisplayName}'
