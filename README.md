# Migrate-automation-account-assets-from-one-region-to-another
This PowerShell script is for migration of Automation account assets from the account in primary region to the account in secondary region. This script migrates only Runbooks, Modules, Connections, Credentials, Certificates and Variables.
### Prerequisites:

1. Ensure that the Automation account in the secondary region is created and available so that assets from primary region can be migrated to it. It is preferred if the destination automation account is one without any custom resources as it prevents potential resource clash due to same name and loss of data
2. System Managed Identities should be enabled in the Automation account in the primary region.
3. System Managed Identities of the Source automation account should have contributor access to the subscription it belongs to
4. Ensure that Primary Automation account's Managed Identity has Contributor access with read and write permissions to the Automation account in secondary region. You can enable it by providing the necessary permissions in Secondary Automation accounts managed identities.
5. This script requires access to Automation account assets in primary region. Hence, it should be executed as a runbook in that Automation account for successful migration.
6. Both the source and destination Automation accounts should belong to the same Azure Active Directory(AAD) tenant
### Follow the steps to import and execute the runbook:

1. Sign in to the Azure portal.
2. Go to Automation account that you want to migrate to another region.
3. Under Process Automation, select Runbooks.
4. Select Browse gallery and in the search, enter "Migrate Automation account assets from one region to another" and Select.
5. In the Import a runbook page, enter a name for the runbook.
6. Select Runtime version as either 5.1 or 7.1 (preview) (preferably 5.1 for now, but it works for either)
7. Enter the description and select Import.
8. In the Edit PowerShell Runbook page, edit the required parameters and execute it.
9. You can choose either of the options to edit and execute the script. You can provide the seven mandatory parameters as given in Option 1 or three mandatory parameters given in Option 2 to edit and execute the script:
	1. Option 1:
		1. SourceAutomationAccountName
		2. DestinationAutomationAccountName
		3. SourceResourceGroup
		4. DestinationResourceGroup
		5. SourceSubscriptionId
		6. DestinationSubscriptionId
		7. LocationDestinationAccount
		8. Type[]
	2. Option 2:
		1. SourceAutomationAccountResourceId
		2. DestinationAutomationAccountResourceId
		3. LocationDestinationAccount
		4. Type[] 
	
