
#++++++++++++++++++++++++++++++Do not run it, it is just so that you know what subscription ID  is which +++++
Select-AzureRmSubscription -SubscriptionId "33bd304f-367f-4b72-a3ea-7d3576781ceb" #Ignite Subscription
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#             DONOT PRESS F5, THE SCRIPT IS NOT WRITTEN TO SUPPORT IT, USE "RUN SELECTION - F8 "
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


########### Deploy the cluster - secure parms and template

$resourceGroup = "chackmip1"
$templateParmfile= "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\Multi Region Spanning Sample\Secure\ServiceFabricCluster2nodetype3Regionsecure.parameters.json"
$templateFile = "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\Multi Region Spanning Sample\Secure\ServiceFabricCluster2nodetype3RegionSecure.json"
$locName="eastus2"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"

Login-AzureRmAccount
Select-AzureRmSubscription -SubscriptionId $SubID 

Remove-AzureRmResourceGroup -Name $resourceGroup -Force

New-AzureRmResourceGroup -Location $locName -Name $resourceGroup

Test-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateParameterFile $templateParmfile -TemplateUri $templateFile -clusterName $resourceGroup -Debug

New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateParameterFile $templateParmfile -TemplateUri $templateFile -clusterName $resourceGroup -Verbose

########### Connecting to the cluster - RDP user chacko, Password - Password!1

$ClusterName= "xrg1-s3.eastus2.cloudapp.azure.com:19000"
$CertThumbprint= "14BF12E423F7CFFA69F18D69DE80A047C818BD4B" 

Connect-serviceFabricCluster -ConnectionEndpoint $ClusterName -KeepAliveIntervalInSec 10 `
    -X509Credential `
    -ServerCertThumbprint $CertThumbprint  `
    -FindType FindByThumbprint `
    -FindValue $CertThumbprint `
    -StoreLocation CurrentUser `
    -StoreName My

##### Get cluster health and other checks
Get-ServiceFabricClusterHealth


