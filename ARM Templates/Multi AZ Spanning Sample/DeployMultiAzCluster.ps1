#++++++++++++++++++++++++++++++Do not run it, it is just so that you know what subscription ID  is which +++++
Select-AzureRmSubscription -SubscriptionId "6c653126-e4ba-42cd-a1dd-f7bf96ae7a47" #build Subscription
Select-AzureRmSubscription -SubscriptionId "33bd304f-367f-4b72-a3ea-7d3576781ceb" #Ignite Subscription
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#             DONOT PRESS F5, THE SCRIPT IS NOT WRITTEN TO SUPPORT IT, USE "RUN SELECTION - F8 "
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Login-AzureRmAccount
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb" #Ignite Subscription
Select-AzureRmSubscription -SubscriptionId $SubID 


$resourceGroup = "chacxaz6"
$templateParmfile= "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\Multi AZ Spanning Sample\5-VM-1-NodeType-Multi-AZ-Secure_ManagedDisk.chacko.Parameters.json"
$templateFile = "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\Multi AZ Spanning Sample\5-VM-1-NodeType-Multi-AZ-Secure_ManagedDisk.json"
$locName="eastus2"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"

Remove-AzureRmResourceGroup -Name $resourceGroup -Force

New-AzureRmResourceGroup -Location $locName -Name $resourceGroup

Test-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateParameterFile $templateParmfile -TemplateUri $templateFile -clusterName $resourceGroup -Debug

New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateParameterFile $templateParmfile -TemplateUri $templateFile -clusterName $resourceGroup -Verbose 