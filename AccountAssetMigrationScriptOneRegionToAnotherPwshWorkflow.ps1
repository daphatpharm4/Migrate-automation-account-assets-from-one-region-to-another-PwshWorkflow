<#
.SYNOPSIS
	This PowerShell script is for migration of Automation account assets from the account in primary region to the account in secondary region. This script migrates only Runbooks, Modules, Connections, Credentials, Certificates and Variables.
	Prerequisites:
		1.Ensure that the Automation account in the secondary region is created and available so that assets from primary region can be migrated to it. It is preferred if the destination automation account is one without any custom resources as it prevents potential resource clash due to same name and loss of data
		2.System Managed Identities should be enabled in the Automation account in the primary region.
		3.System Managed Identities of the Source automation account should have contributor access to the subscription it belongs to
		4.Ensure that Primary Automation account's Managed Identity has Contributor access with read and write permissions to the Automation account in secondary region. You can enable it by providing the necessary permissions in Secondary Automation accountâ€™s managed identities. Learn more
		5.This script requires access to Automation account assets in primary region. Hence, it should be executed as a runbook in that Automation account for successful migration.
		6.Both the source and destination Automation accounts should belong to the same Azure Active Directory(AAD) tenant
.PARAMETER SourceAutomationAccountName
	[Optional] Name of automation account from where assets need to be migrated (Source Account)
.PARAMETER DestinationAutomationAccountName
	[Optional] Name of automation account to where assets need to be migrated (Destination Account)
.PARAMETER SourceResourceGroup
	[Optional] Resource group to which the automation account from where assets need to be migrated
.PARAMETER DestinationResourceGroup
	[Optional] Resource group to which the automation account to where assets need to be migrated
.PARAMETER SourceSubscriptionId
	[Optional] Id of the Subscription to which the automation account from where assets need to be migrated
.PARAMETER DestinationSubscriptionId
	[Optional] Id of the Subscription to which the automation account to where assets need to be migrated
.PARAMETER SourceAutomationAccountResourceId
	[Optional] Resource Id of the automation account from where assets need to be migrated
.PARAMETER DestinationAutomationAccountResourceId
	[Optional] Resource Id of the automation account to where assets need to be migrated
.PARAMETER LocationDestinationAccount
	[Mandatory] Location of the destination automation account
.PARAMETER Type[]
	[Mandatory] Array consisting of all the types of assets that need to be migrated, possible values are Certificates, Connections, Credentials, Modules, Runbooks, and Variables.
.NOTES
	1. Script for Migrations from-> Source account to Destination Account (will have to be created for now)
	2. Please do the following for the execution of script if source account's managed identity does not have read write access control of the destination account:
		• Get into the destination account and grant access of destination account to your source account's managed identity using this guide Tutorial: https://docs.microsoft.com/en-us/azure/role-based-access-control/quickstart-assign-role-user-portal
.AUTHOR Microsoft
.VERSION 1.0
#>
#Requires -module @{ ModuleName="Az.Accounts"; ModuleVersion="	2.8.0" },@{ ModuleName="Az.Resources"; ModuleVersion="	6.0.0" },@{ ModuleName="Az.Automation"; ModuleVersion="1.7.3" },@{ ModuleName="Az.Storage"; ModuleVersion="4.6.0" }
#Requires -psedition Core

workflow Migration{

	param(
		[Parameter(Mandatory=$False)][string]$SourceAutomationAccountName,
		[Parameter(Mandatory=$False)][string]$DestinationAutomationAccountName,
		[Parameter(Mandatory=$False)][string]$SourceResourceGroup,
		[Parameter(Mandatory=$False)][string]$DestinationResourceGroup,
		[Parameter(Mandatory=$False)][string]$SourceSubscriptionId,
		[Parameter(Mandatory=$False)][string]$DestinationSubscriptionId,
		[Parameter(Mandatory=$False)][string]$SourceAutomationAccountResourceId,
		[Parameter(Mandatory=$False)][string]$DestinationAutomationAccountResourceId,
		[Parameter(Mandatory=$True)][string]$LocationDestinationAccount
		[Parameter(Mandatory=$True)][string[]]$Types	
	)

	inlinescript
	{
		
		$Version="1.0"
		Write-Output "Version $Version"


		try
		{
			"Logging in to Azure..."
			Connect-AzAccount -Identity
		}
		catch {
			Write-Error -Message $_.Exception
			throw $_.Exception
		}

		$SourceAutomationAccountName= $using:SourceAutomationAccountName
		$SourceResourceGroup= $using:SourceResourceGroup
		$SourceSubscriptionId= $using:SourceSubscriptionId
		$SourceAutomationAccountResourceId= $using:SourceAutomationAccountResourceId
		
		$DestinationAutomationAccountName= $using:DestinationAutomationAccountName
		$DestinationResourceGroup= $using:DestinationResourceGroup
		$DestinationSubscriptionId= $using:DestinationSubscriptionId
		$DestinationAutomationAccountResourceId= $using:DestinationAutomationAccountResourceId
		$LocationDestinationAccount= $using:LocationDestinationAccount
		$Types= $using:Types


		Function ParseReourceID($resourceID)
		{
			$array = $resourceID.Split('/') 
			$indexRG = 0..($array.Length -1) | where {$array[$_] -eq 'resourcegroups'}
			$indexSub = 0..($array.Length -1) | where {$array[$_] -eq 'subscriptions'}
			$indexAA =0..($array.Length -1) | where {$array[$_] -eq 'automationAccounts'}
			$result = $array.get($indexRG+1),$array.get($indexSub+1),$array.get($indexAA+1)
			return $result
		}

		Function RandomStringProducer
		{
			$TokenSet = @{
				L = [Char[]]'abcdefghijklmnopqrstuvwxyz'
				N = [Char[]]'0123456789'
			}


			$Lower = Get-Random -Count 10 -InputObject $TokenSet.L
			$Number = Get-Random -Count 10 -InputObject $TokenSet.N


			$StringSet = $Lower + $Number
			$RandomString=(Get-Random -Count 15 -InputObject $StringSet) -join ''
			return $RandomString
		}

		Function CheckifInputIsValid($In)
		{
			if ([string]::IsNullOrWhiteSpace($In))
			{
			return $False
			}
			return $True
		}

		Function Test-IsGuid
		{
			[OutputType([bool])]
			param
			(
				[Parameter(Mandatory = $true)]
				[string]$StringGuid
			)

			$ObjectGuid = [System.Guid]::empty
			return [System.Guid]::TryParse($StringGuid,[System.Management.Automation.PSReference]$ObjectGuid) # Returns True if successfully parsed
		}

		#Get bearer token for authentication
		Function Get-AzCachedAccessToken() 
		{
			$token=Get-AzAccessToken 
			return [String]$token.Token
		}


		#Module transfer helper functions

		Function StoreModules($Modules_Custom)
		{

			Foreach($Module in $Modules_Custom)
			{


				$ModuleName = $Module
				$ModulePath="C:\Modules\User\"+$ModuleName
				$ModuleZipPath="C:\"+ $tempFolder+"\"+$ModuleName+".zip"
				try
				{
					Compress-Archive -LiteralPath $ModulePath -DestinationPath $ModuleZipPath
				}
				catch
				{
					Write-Error -Message "Unable to store custom modules, error while accessing the temprary memory. Error Message: $($Error[0].Exception.Message)"
				}
			}

		}

		Function ValidateDestinationSubId($SubscriptionId)
		{	
			$SubscriptionsFullDetails=Get-AzSubscription
			$SubIds=$SubscriptionsFullDetails.SubscriptionId
			foreach($sub in $SubIds )
			{
				if($sub -eq $SubscriptionId)
				{
					return $true
				}
			}
			return $false

		}

		Function CreateStorageAcc($StorageAccountName, $storageAccountRG)
		{
			New-AzStorageAccount -ResourceGroupName $storageAccountRG -Name $StorageAccountName -Location westus -SkuName Standard_LRS
			$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $storageAccountRG -AccountName $storageAccountName).Value[0]
			return $storageAccountKey

		}

		Function CreateContainer($Context,$storageContainerName)
		{
			New-AzStorageContainer -Name $storageContainerName -Context $Context -Permission Container
		}


		Function SendToBlob($Modules)
		{

			# Set AzStorageContext
			[String]$storageAccountKey = CreateStorageAcc $StorageAccountName $storageAccountRG
			if($null -ne $storageAccountKey)
			{
				$Context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
				try
				{
					CreateContainer $Context $storageContainerName
					Foreach($Module in $Modules)
					{
						$ModuleName = $Module
						$ModuleZipPath="C:\"+$tempFolder+"\"+$ModuleName+".zip"
						"Retrieving files from module: $ModuleName to save to container: $storageContainerName"
						Set-AzStorageBlobContent -File $ModuleZipPath -Container $storageContainerName -Context $Context	
					}
				}
				catch
				{
					Write-Error -Message "Unable to store custom modules, error while creating and transfering modules to temprory storage account. Error Message: $($Error[0].Exception.Message)"
				}

			}
			else
			{
				Write-Error "Unable to create a new temprory storage account for transfer of modules, please ensure you have appropriate permissions for the subscription- $SourceSubscriptionId "
			}



		}

		Function RemoveStorageAcc($StorageAccountName, $StorageAccountRG, $SubscriptionId)
		{
			Set-Context($SubscriptionId)
			Remove-AzStorageAccount -ResourceGroupName $StorageAccountRG  -Name $StorageAccountName -Force
		}

		#setting context
		Function Set-Context($SubscriptionId)
		{
			try
			{
				Set-AzContext -SubscriptionId $SubscriptionId
			}
			catch 
			{
				Write-Error -Message $_.Exception
				throw $_.Exception
			}
		}

		#-----------------------------------------------------------------------------------------------------------------------
		# Import Asset functions


		Function Import-RunbooksFromOldAccount{
			$Runbooks = Get-AzAutomationRunbook -ResourceGroupName $SourceResourceGroup -AutomationAccountName $SourceAutomationAccountName
			if(!$?)
			{
				Write-Error "Failed to retrieve runbooks from automation account \' $SourceAutomationAccountName \'"
			}
			return $Runbooks
		}

		Function Import-VariablesFromOldAccount{
			$Variables=Get-AzAutomationVariable -AutomationAccountName $SourceAutomationAccountName -ResourceGroupName $SourceResourceGroup
			if(!$?)
			{
				Write-Error "Failed to retrieve variables from automation account \' $SourceAutomationAccountName \'"
			}
			return $Variables
		}

		Function Import-CredentialsFromOldAccount{
			$Credentials=Get-AzAutomationCredential -ResourceGroupName $SourceResourceGroup -AutomationAccountName $SourceAutomationAccountName 
			if(!$?)
			{
				Write-Error "Failed to retrieve credentials from automation account \' $SourceAutomationAccountName \'"
			}
			return $Credentials
		}

		Function Import-CertificatesFromOldAccount
		{
			$Certificates=Get-AzAutomationCertificate -ResourceGroupName $SourceResourceGroup -AutomationAccountName $SourceAutomationAccountName 
			if(!$?)
			{
				Write-Error "Failed to retrieve certificates from automation account \' $SourceAutomationAccountName \'"
			}
			return $Certificates
		}

		Function Import-ConnectionsFromOldAccount{
			$Connections=Get-AzAutomationConnection -ResourceGroupName $SourceResourceGroup -AutomationAccountName $SourceAutomationAccountName 
			if(!$?)
			{
				Write-Error "Failed to retrieve connections from automation account \' $SourceAutomationAccountName \'"
			}
			return $Connections
		}

		Function Import-PwshModulesFromOldAccount
		{
			$AllModules= Get-AzAutomationModule -AutomationAccountName $SourceAutomationAccountName -ResourceGroupName $SourceResourceGroup 
			if(!$?)
			{
				Write-Error "Failed to retrieve modules from automation account ' $SourceAutomationAccountName '"
			}
			$ModulesRequired = $AllModules.name
			$Modules_Custom = Get-ChildItem -Path "C:\Modules\User\" | ?{$_.Attributes -eq "Directory"} | where Name -match $($ModulesRequired -join '|') 
			return $Modules_Custom

		}

		#-------------------------------------------------------------------------------------------------------------------------------------------


		#Export Assets functions
		Function Export-RunbooksToNewAccount($Runbooks)
		{
			foreach($Runbook in $Runbooks)
			{
				[string]$CurrentRunbookType=$Runbook.RunbookType
				[string]$RunbookName=$Runbook.Name
				$Location=$Runbook.Location
				$LogProgress= $Runbook.logProgress
				$LogVerbose= $Runbook.logVerbose
				$Tags= $Runbook.Tags
				$JobCount= $Runbook.JobCount
				$Parameters = $Runbook.Parameters
				$LastModifiedBy = $Runbook.LastModifiedBy
				$State = $Runbook.State
				$CreationTime = $Runbook.CreationTime
				$LastModifiedTime = $Runbook.LastModifiedTime
				$Description= $Runbook.Description
				$bearerToken = Get-AzCachedAccessToken
				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken";
					}
					$ContentLink= @{
						"uri" = "https://raw.githubusercontent.com/azureautomation/Migrate-automation-account-assets-from-one-region-to-another/main/DummyRunbook.ps1";
					}

					$draft= @{
						"draftContentLink"= $ContentLink;
						"inEdit" = $False;
					}		
					$properties= @{
						"logVerbose"= $LogVerbose;
						"logProgress"= $LogProgress;
						"runbookType"= $CurrentRunbookType;
						"state"=$State;
						"draft"=$draft;
						"description"= $Description;
						}
					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/runbooks/"+$RunbookName+"?api-version=2019-06-01"	
					$Body = @{
						"name"= $RunbookName;
						"properties"= $properties;
						"location"=$LocationDestinationAccount;
						"tags"=$Tags
					}
					$bodyjson=($Body| ConvertTo-Json  -Depth 4)
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri $url -Body $bodyjson -ContentType "application/json" -Headers $Headers

						if($State -eq "New")
						{
							$urlGetContent= "https://management.azure.com/subscriptions/"+$SourceSubscriptionId+"/resourceGroups/"+$SourceResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$SourceAutomationAccountName+"/runbooks/"+$RunbookName+"/draft/content?api-version=2019-06-01"
							$rbContentDraft=Invoke-RestMethod -Method "GET" -Uri "$urlGetContent" -ContentType "application/json" -Headers $Headers
							$urlPutContent= "https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/runbooks/"+$RunbookName+"/draft/content?api-version=2019-06-01"
							Invoke-RestMethod -Method "PUT" -Uri "$urlPutContent" -Body $rbContentDraft -Headers $Headers
						}
						else
						{
							$urlGetContent= "https://management.azure.com/subscriptions/"+$SourceSubscriptionId+"/resourceGroups/"+$SourceResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$SourceAutomationAccountName+"/runbooks/"+$RunbookName+"/content?api-version=2019-06-01"
							$rbContent=Invoke-RestMethod -Method "GET" -Uri "$urlGetContent" -ContentType "application/json" -Headers $Headers
							$urlPutContent= "https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/runbooks/"+$RunbookName+"/draft/content?api-version=2019-06-01"
							Invoke-RestMethod -Method "PUT" -Uri "$urlPutContent" -Body $rbContent -Headers $Headers
							$urlPublish= "https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/runbooks/"+$RunbookName+"/publish?api-version=2019-06-01"
							Invoke-RestMethod -Method "POST" -Uri "$urlPublish" -Body "" -Headers $Headers
							if($State -eq "Edit")
							{
								$urlGetContentDraft= "https://management.azure.com/subscriptions/"+$SourceSubscriptionId+"/resourceGroups/"+$SourceResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$SourceAutomationAccountName+"/runbooks/"+$RunbookName+"/draft/content?api-version=2019-06-01"
								$rbContentDraft=Invoke-RestMethod -Method "GET" -Uri "$urlGetContentDraft" -ContentType "application/json" -Headers $Headers
								$urlPutContentDraft= "https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/runbooks/"+$RunbookName+"/draft/content?api-version=2019-06-01"
								Invoke-RestMethod -Method "PUT" -Uri "$urlPutContentDraft" -Body $rbContentDraft -Headers $Headers
							}
						}


					}
					catch{
						Write-Error -Message "Unable to import runbook ' $RunbookName ' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
					}

				}

			}
		}

		Function Export-VariablesToNewAccount($Variables)
		{
			$bearerToken = Get-AzCachedAccessToken
			foreach($Variable in $Variables)
			{	
				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken"
					}

					[string]$VariableName=$Variable.Name
					$VariableEncryption=$Variable.Encrypted
					$VariableDesc=$Variable.Description
					$VariableValue=Get-AutomationVariable -Name $VariableName
					$properties= @{
								"value"= $VariableValue;
								"isEncrypted"= $VariableEncryption;
								"description"= $VariableDesc;
								}
					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/variables/"+$VariableName+"?api-version=2019-06-01"	
					$Body = @{
								"name"= $VariableName;
								"properties"= $properties;
							}
					$bodyjson=($Body| ConvertTo-Json )
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri "$url" -Body $bodyjson -ContentType "application/json" -Headers $Headers
					}
					catch
					{
						try
						{
							Set-AzAutomationVariable -AutomationAccountName $DestinationAutomationAccountName  -Name $VariableName -Encrypted $VariableEncryption -Value $VariableValue -ResourceGroupName $DestinationResourceGroup -Description $VariableDesc
						}
						catch
						{
							try
							{
								New-AzAutomationVariable -AutomationAccountName $DestinationAutomationAccountName  -Name $VariableName -Encrypted $VariableEncryption -Value $VariableValue -ResourceGroupName $DestinationResourceGroup -Description $VariableDesc
							}
							catch
							{
								Write-Error -Message "Unable to import Variable '$VariableName' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
							}

						}

					}

				}
				else{
					Write-Error "Unable to retrieve the authentication token for the account $DestinationAutomationAccountName"
				}

			}
		}

		Function Export-CredentialsToNewAccount($Credentials)
		{
			$bearerToken = Get-AzCachedAccessToken
			foreach($Credential in $Credentials)
			{
				$CredentialName=$Credential.Name
				$getCredential = Get-AutomationPSCredential -Name $CredentialName
				$Username=$getCredential.username	
				$Password = $getCredential.GetNetworkCredential().Password
				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken"
					}
					$properties= @{
								"username"= $Username;
								"password"= $Password;
								"description"= $Credential.Description;
								}
					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/credentials/"+$CredentialName+"?api-version=2019-06-01"	
					$Body = @{
								"name"= $CredentialName;
								"properties"= $properties;
							}
					$bodyjson=($Body| ConvertTo-Json )
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri "$url" -Body $bodyjson -ContentType "application/json" -Headers $Headers
					}
					catch
					{
						try
						{
							New-AzAutomationCredential -AutomationAccountName $DestinationAutomationAccountName -Name $CredentialName -Value $getCredential -ResourceGroupName $DestinationResourceGroup
						}
						catch
						{
							Write-Error -Message "Unable to import credentials '$CredentialName' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
						}
					}
				}
				else
				{
					Write-Error "Unable to retrieve the authentication token for the account $DestinationAutomationAccountName"
				}

			}
		}

		Function Export-ConnectionsToNewAccount($Connections)
		{
			$bearerToken = Get-AzCachedAccessToken
			foreach($Connection in $Connections)
			{
				$ConnectionType=$Connection.ConnectionTypeName
				$ConnectionFieldValues
				$ConnectionName=$Connection.Name
				$getConnection= Get-AutomationConnection $Connection.Name
				if($ConnectionType -eq "AzureClassicCertificate")
				{
					$SubscriptionName = $getConnection.SubscriptionName
					$SubscriptionId = $getConnection.SubscriptionId
					$ClassicRunAsAccountCertifcateAssetName = $getConnection.CertificateAssetName
					$ConnectionFieldValues = @{"SubscriptionName" = $SubscriptionName; "SubscriptionId" = $SubscriptionId; "CertificateAssetName" = $ClassicRunAsAccountCertifcateAssetName}
				}
				if($ConnectionType -eq "AzureServicePrincipal")
				{

					$Thumbprint = $getConnection.CertificateThumbprint
					$TenantId = $getConnection.TenantId
					$ApplicationId = $getConnection.ApplicationId
					$SubscriptionId = $getConnection.SubscriptionId
					$ConnectionFieldValues = @{"ApplicationId" = $ApplicationId; "TenantId" = $TenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $SubscriptionId}

				}

				if($ConnectionType -eq "Azure")
				{
					$ConnectionFieldValues = @{"AutomationCertificateName"=$getConnection.AutomationCertificateName;"SubscriptionID"=$getConnection.SubscriptionId}
				}

				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken"
					}
					$ConnectionTypeName= @{
						"name"= $ConnectionType;
					}
					$properties= @{
								"fieldDefinitionValues"= $ConnectionFieldValues;
								"connectionType"= $ConnectionTypeName;
								"description"= $Connection.Description;
								}
					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/connections/"+$ConnectionName+"?api-version=2019-06-01"	
					$Body = @{
								"name"= $ConnectionName;
								"properties"= $properties;
							}
					$bodyjson=($Body| ConvertTo-Json )
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri "$url" -Body $bodyjson -ContentType "application/json" -Headers $Headers
					}
					catch
					{
						try
						{
							New-AzAutomationConnection -Name $Connection.Name -ConnectionTypeName $ConnectionType  -ConnectionFieldValues $ConnectionFieldValues -ResourceGroupName $DestinationResourceGroup -AutomationAccountName $DestinationAutomationAccountName
						}
						catch
						{
							Write-Error -Message "Unable to import connection '$ConnectionName' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
						}
					}
				}

				else
				{
					Write-Error "Unable to retrieve the authentication token for the account $DestinationAutomationAccountName"
				}

			}
		}

		Function Export-CertificatesToNewAccount($Certificates)
		{
			$bearerToken = Get-AzCachedAccessToken
			foreach($Certificate in $Certificates)
			{
				$CertificateName=$Certificate.Name
				$getCertificate=Get-AutomationCertificate -Name $CertificateName
				$ASNFormatCertificate=$getCertificate.GetRawCertData()
				if($Certificate.Exportable -eq $True)
				{
					$ASNFormatCertificate=$getCertificate.Export("pfx")
				}
				[string]$Base64Certificate =[Convert]::ToBase64String($ASNFormatCertificate)
				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken"
					}

					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/certificates/"+$CertificateName+"?api-version=2019-06-01"	
					$properties= @{
						"base64Value"= $Base64Certificate;
						"description"= $Certificate.description;
						"thumbprint"= $getCertificate.Thumbprint;
						"isExportable"= $Certificate.Exportable;
					}
					$Body = @{
						"name"= $CertificateName;
						"properties"= $properties 
					}
					$bodyjson=($Body| COnvertTo-Json)
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri "$url" -Body $bodyjson -ContentType "application/json" -Headers $Headers
					}
					catch
					{
						Write-Error -Message "Unable to import cerficate '$CertificateName' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
					}

				}
				else{
					Write-Error "Unable to retrieve the authentication token for the account $DestinationAutomationAccountName"
				}
			}

		}

		Function Export-PwshModulesToNewAccount($Modules)
		{
			$bearerToken = Get-AzCachedAccessToken
			Foreach($Module in $Modules)
			{

				$ModuleName = $Module
				if($null -ne $bearerToken)
				{
					$Headers = @{
						"Authorization" = "Bearer $bearerToken"
					}
					$BlobURL="https://"+$StorageAccountName+".blob.core.windows.net/"+$storageContainerName+"/"+$ModuleName+".zip"
					# New-AzAutomationModule -AutomationAccountName $DestinationAutomationAccountName -Name $ModuleName -ContentLink $BlobURL -ResourceGroupName $DestinationResourceGroup
					$url="https://management.azure.com/subscriptions/"+$DestinationSubscriptionId+"/resourceGroups/"+$DestinationResourceGroup+"/providers/Microsoft.Automation/automationAccounts/"+$DestinationAutomationAccountName+"/modules/"+$ModuleName+"?api-version=2019-06-01"	
					$ContentLink=@{
						"uri"= $BlobURL
					}
					$properties= @{
						"contentLink"= $ContentLink;
						"version"= "1.0.0.0"
					}
					$Body = @{
						"properties"= $properties 
					}
					$bodyjson=($Body| COnvertTo-Json)
					try
					{
						Invoke-RestMethod -Method "PUT" -Uri "$url" -Body $bodyjson -ContentType "application/json" -Headers $Headers
					}
					catch
					{
						Write-Error -Message "Unable to import module '$ModuleName' to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
					}
				}
				else{
					Write-Error "Unable to retrieve the authentication token for the account $DestinationAutomationAccountName"
				}

			}
		}

		#---------------------------------------------------------------------------------------------------------------------------------------------------
		#Transfer function

		Function TransferRunbooks
		{
			Set-Context $SourceSubscriptionId
			$Runbooks = Import-RunbooksFromOldAccount
			if($null -ne $Runbooks)
			{
				$Runbooks | Export-AzAutomationRunbook -OutputFolder $LocalStoragePath -Force  
				Set-Context $DestinationSubscriptionId
				Export-RunbooksToNewAccount $Runbooks
			}
			else
			{
				Write-Error "Unable to find any runbooks associated with the account name $SourceAutomationAccountName"
			}
		}


		Function TransferVariables
		{
			Set-Context $SourceSubscriptionId
			$Variables = Import-VariablesFromOldAccount
			if($null -ne  $Variables)
			{
				Set-Context $DestinationSubscriptionId
				Export-VariablesToNewAccount $Variables
			}
			else
			{
				Write-Error "Unable to find any variables associated with the account name $SourceAutomationAccountName"
			}
		}

		Function TransferCredentials
		{
			Set-Context $SourceSubscriptionId
			$Credentials= Import-CredentialsFromOldAccount
			if($null -ne $Credentials)
			{
				Set-Context $DestinationSubscriptionId
				Export-CredentialsToNewAccount $Credentials
			}
			else
			{
				Write-Error "Unable to find any credentials associated with the account name $SourceAutomationAccountName"
			}
		}

		Function TransferConnections
		{
			Set-Context $SourceSubscriptionId
			$Connections=Import-ConnectionsFromOldAccount
			if($null -ne $Connections)
			{
				Set-Context $DestinationSubscriptionId
				Export-ConnectionsToNewAccount $Connections
			}
			else
			{
				Write-Error "Unable to find any connections associated with the account name $SourceAutomationAccountName"
			}

		}

		Function TransferCertificates
		{
			Set-Context $SourceSubscriptionId
			$Certificates=Import-CertificatesFromOldAccount
			if($null -ne $Certificates)
			{
				Set-Context $DestinationSubscriptionId
				Export-CertificatesToNewAccount $Certificates 
			}
			else
			{
				Write-Error "Unable to find any certificates associated with the account name $SourceAutomationAccountName"
			}
		}

		Function TransferModules
		{
			Set-AzContext -SubscriptionId $SourceSubscriptionId
			New-Item -Path "C:\$tempFolder" -ItemType Directory
			$modules=Import-PwshModulesFromOldAccount
			if($null -ne $modules)
			{
				StoreModules $modules
				SendToBlob $modules
				Set-AzContext -SubscriptionId $DestinationSubscriptionId
				try
				{
					Export-PwshModulesToNewAccount $modules
				}
				catch
				{
					Write-Error -Message "Unable to transfer modules to account $DestinationAutomationAccountName. Error Message: $($Error[0].Exception.Message)"
				}
				RemoveStorageAcc $storageAccountName $storageAccountRG $subscriptionId
			}
			else
			{
				Write-Error "Unable to find any powershell modules associated with the account name $SourceAutomationAccountName"
			}
		}

		if($SourceAutomationAccountResourceId.Length -ne 0)
		{
			try
			{
				$parsedResourceID=ParseReourceID $SourceAutomationAccountResourceId
				$SourceResourceGroup=$parsedResourceID[0]
				$SourceSubscriptionId=$parsedResourceID[1]
				$SourceAutomationAccountName=$parsedResourceID[2]
			}
			catch
			{
				throw "Invalid source account resource ID entered"
			}

		}

		if($DestinationAutomationAccountResourceId.Length -ne 0)
		{
			try
			{
				$parsedResourceID=ParseReourceID $DestinationAutomationAccountResourceId
				$DestinationResourceGroup=$parsedResourceID[0]
				$DestinationSubscriptionId=$parsedResourceID[1]
				$DestinationAutomationAccountName=$parsedResourceID[2]
			}
			catch
			{
				throw "Invalid source account resource ID entered"
			}
		}

		$LocalStoragePath= ".\"
		$subscriptionId = $SourceSubscriptionId
		$storageAccountRG = $SourceResourceGroup
		$storageAccountName = RandomStringProducer
		$storageContainerName = "migrationcontainer"
		$tempFolder=RandomStringProducer

		$Access=0
		if(CheckifInputIsValid($SourceAutomationAccountName) -and CheckifInputIsValid($SourceResourceGroup) -and CheckifInputIsValid($SourceSubscriptionId) -and CheckifInputIsValid($DestinationAutomationAccountName) -and CheckifInputIsValid($DestinationResourceGroup) -and CheckifInputIsValid($DestinationSubscriptionId))
		{
			if((Test-IsGuid $SourceSubscriptionId) -and (Test-IsGuid $DestinationSubscriptionId))
			{
				if(ValidateDestinationSubId $DestinationSubscriptionId)	
				{
					foreach($assestType in $Types)
					{
						if($assestType -eq "Runbooks")
						{
							TransferRunbooks
						}
						elseif($assestType -eq "Variables")
						{
							TransferVariables
						}
						elseif($assestType -eq "Connections")
						{
							TransferConnections
						}
						elseif($assestType -eq "Credentials")
						{
							TransferCredentials
						}
						elseif($assestType -eq "Certificates")
						{
							TransferCertificates
						}
						elseif($assestType -eq "Modules")
						{
							TransferModules
						}
						else{
							Write-Error "Please enter a valid type as $assestType is not a valid option, acceptable options are: Certificates, Connections, Credentials, Modules, Runbooks, Variables"
						}

					}
				}
				else{
					Write-Error "Please ensure source account's managed Identity has contributor access with read and write privileges to the destination account(https://docs.microsoft.com/en-us/azure/role-based-access-control/quickstart-assign-role-user-portal)"
				}

			}
			else
			{
				Write-Error "Please enter valid Source and Destination subscription IDs"
			}
		}
		else
		{
			Write-Error "Please enter valid Inputs(either Source and Destination Resource IDs or Source and Destination Subscription IDs, Resource Group names and Automation account names)"
		}

	}
		
}

