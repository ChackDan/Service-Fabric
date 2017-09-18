
#++++++++++++++++++++++++++++++Do not run it, it is just so that you know what subscription ID  is which +++++
Select-AzureRmSubscription -SubscriptionId "6c653126-e4ba-42cd-a1dd-f7bf96ae7a47" #build Subscription
Select-AzureRmSubscription -SubscriptionId "33bd304f-367f-4b72-a3ea-7d3576781ceb" #Ignite Subscription
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#             DONOT PRESS F5, THE SCRIPT IS NOT WRITTEN TO SUPPORT IT, USE "RUN SELECTION - F8 "
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$RGroup = "xrg3"
$ResouceGroup = "chackoewestuskv"
$VName = "westuskv2"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "westus" 
$newCertName = "chackonewcertificate5"
$certPassword = "Password!1"
$dnsName = "www.chacko2017.new.certificate.azure.com"
$localCertPath = "C:\MyCertificates"

#+++++++++++++++++++++++++++ reusse an exisitng cer

Add-AzureRmServiceFabricApplicationCertificate -ResourceGroupName $RGroup -KeyVaultResouceGroupName $ResouceGroup -Name $RGroup -KeyVaultName $VName -CertificateFile C:\MyCertificates\chackonewcertificate5.pfx -CertificatePassword (ConvertTo-SecureString -String Password!1 -AsPlainText -Force) 



## Download the Module from  https://github.com/ChackDan/Service-Fabric/tree/master/Scripts/ServiceFabricRPHelpers and navigate to the folder.
## navigatge to the folder where you downloaded the helper.
Import-Module C:\Users\chackdan\Documents\GitHub\Service-Fabric\Scripts\ServiceFabricRPHelpers\ServiceFabricRPHelpers.psm1

## create new RG and new Keyvault and new self signed cert for use.
Login-AzureRmAccount
Select-AzureRmSubscription -SubscriptionId $SubID 

New-AzureRmKeyVault -VaultName $VName -ResourceGroupName $ResouceGroup -Location $LocationRegion -EnabledForDeployment

Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName -CertificateName $newCertName -Password $certPassword -CreateSelfSignedCertificate -DnsName $dnsName -OutputPath $localCertPath

Set-AzureRmKeyVaultAccessPolicy -VaultName $VName -ResourceGroupName $ResouceGroup -EnabledForDeployment

# make sure to copy the output to a safe place. you will need it. I have copied it to the end of this doc..

######## Set up the certs on your local box
Import-PfxCertificate -Exportable -CertStoreLocation Cert:\CurrentUser\TrustedPeople -FilePath C:\MyCertificates\chackonewcertificate1.pfx -Password (ConvertTo-SecureString -String Password!1 -AsPlainText -Force)
Import-PfxCertificate -Exportable -CertStoreLocation Cert:\CurrentUser\My -FilePath C:\MyCertificates\chackonewcertificate1.pfx -Password (ConvertTo-SecureString -String Password!1 -AsPlainText -Force)


######## use the existing Certificate and deploy to Second region keyvaults

$ResouceGroup = "chackoeastuskv"
$VName = "eastuskv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "eastus" 
$newCertName = "chackonewcertificate2"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password Password!1
Set-AzureRmKeyVaultAccessPolicy -VaultName $VName -ResourceGroupName $ResouceGroup -EnabledForDeployment

######## use the existing Certificate and deploy to Second region keyvaults

$ResouceGroup = "chackoeastuskv"
$VName = "eastuskv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "eastus" 
$newCertName = "chackonewcertificate1"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password Password!1
Set-AzureRmKeyVaultAccessPolicy -VaultName $VName -ResourceGroupName $ResouceGroup -EnabledForDeployment


######## use the existing Certificate and deploy to Third region keyvaults

$ResouceGroup = "chackoeastus2kv"
$VName = "eastus2kv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "eastus2" 
$newCertName = "chackonewcertificate1"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password Password!1
Set-AzureRmKeyVaultAccessPolicy -VaultName $VName -ResourceGroupName $ResouceGroup -EnabledForDeployment

########## Adding Secondary certs to these keyvaults.###################


#$newCertName = "chackonewcertificate2"
#$certPassword = "Password!1"
#$dnsName = "www.chacko2017.newcertificate.azure.com"
#$localCertPath = "C:\MyCertificates"


######## use the existing Certificate and deploy to Second region keyvaults

$ResouceGroup = "chackowestuskv"
$VName = "westuskv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "westus" 
$newCertName = "chackonewcertificate2"
$certPassword = "Password!1"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password $certPassword


######## use the existing Certificate and deploy to Second region keyvaults

$ResouceGroup = "chackoeastuskv"
$VName = "eastuskv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "eastus" 
$newCertName = "chackonewcertificate2"
$certPassword = "Password!1"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password $certPassword


######## use the existing Certificate and deploy to Third region keyvaults

$ResouceGroup = "chackowestuskv"
$VName = "westuskv1"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"
$locationRegion = "westus" 
$newCertName = "chackonewcertificate1"
$certPassword = "Password!1"


Invoke-AddCertToKeyVault -SubscriptionId $SubID -ResourceGroupName $ResouceGroup -Location $locationRegion -VaultName $VName  -CertificateName $newCertName -UseExistingCertificate -ExistingPfxFilePath C:\MyCertificates\$newCertName.pfx -Password $certPassword
Set-AzureRmKeyVaultAccessPolicy -VaultName $VName -ResourceGroupName $ResouceGroup -EnabledForDeployment

########### Deploy the cluster - unsecure parms and template

$resourceGroup = "xrg7"
$templateParmfile= "C:\Users\chackdan\Documents\GitHub\ClusterTemplates\MultiRegion\Ignite2017\unsecure\ServiceFabricCluster2nodetype3Region.parameters.json"
$templateFile = "C:\Users\chackdan\Documents\GitHub\ClusterTemplates\MultiRegion\Ignite2017\unsecure\ServiceFabricCluster2nodetype3Region.json"
$locName="eastus2"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"

########### Deploy the cluster - unsecure parms and template

$resourceGroup = "xrg2"
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




########  output1 - WestUS cert details

Name  : CertificateThumbprint
Value : 14BF12E423F7CFFA69F18D69DE80A047C818BD4B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackowestuskv/providers/Microsoft.KeyVault/vaults/westuskv1

Name  : CertificateURL
Value : https://westuskv1.vault.azure.net:443/secrets/chackonewcertificate1/0be6522e93694a97bc724fb815f05e24

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate1.pfx
dns name - "www.chacko2017.new.certificate.azure.com"
cert Pwd - Password!1

########  output2 - WestUS cert details
Creating new self signed certificate at C:\MyCertificates\chackonewcertificate5.pfx
Reading pfx file from C:\MyCertificates\chackonewcertificate5.pfx
Writing secret to chackonewcertificate5 in vault westuskv2


Name  : CertificateThumbprint
Value : C4A37F846F98FBE343108B5A9972D9540AE3E30D

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackoewestuskv/providers/Microsoft.KeyVault/vaults/westuskv2

Name  : CertificateURL
Value : https://westuskv2.vault.azure.net:443/secrets/chackonewcertificate5/12c6a5d9c27142b1bcd9ca6ec42234bb

########  output2 - EastUS cert details

Name  : CertificateThumbprint
Value : 14BF12E423F7CFFA69F18D69DE80A047C818BD4B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackoeastuskv/providers/Microsoft.KeyVault/vaults/eastuskv1

Name  : CertificateURL
Value : https://eastuskv1.vault.azure.net:443/secrets/chackonewcertificate1/25a86193546647d8a15df57a93cca9f4

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate1.pfx
dns name - "www.chacko2017.new.certificate.azure.com"
cert Pwd - Password!1


########  output2 - EastUS2 cert details


Name  : CertificateThumbprint
Value : 14BF12E423F7CFFA69F18D69DE80A047C818BD4B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackoeastus2kv/providers/Microsoft.KeyVault/vaults/eastus2kv1

Name  : CertificateURL
Value : https://eastus2kv1.vault.azure.net:443/secrets/chackonewcertificate1/0120db4bb75544c2b95b2f9211bc0ea6

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate1.pfx
dns name - "www.chacko2017.new.certificate.azure.com"
cert Pwd - Password!1

########## For Secondary certificates.

########  output1 - WestUS cert details

Name  : CertificateThumbprint
Value : C2D7E11DD35153A702A51D10A424A3014B9B6E8B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackowestuskv/providers/Microsoft.KeyVault/vaults/westuskv1

Name  : CertificateURL
Value : https://westuskv1.vault.azure.net:443/secrets/chackonewcertificate2/d4c52140c24e48d3bbebf94fecf8b68b

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate1.pfx
dns name - "www.chacko2017.newcertificate.azure.com"
cert Pwd - Password!1


########### output1 west us cert3
Creating new self signed certificate at C:\MyCertificates\chackonewcertificate3.pfx
Reading pfx file from C:\MyCertificates\chackonewcertificate3.pfx
Writing secret to chackonewcertificate3 in vault westuskv1


Name  : CertificateThumbprint
Value : 4068F1F27A0956D06480FE7F29FA1AC94428B718

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackowestuskv/providers/Microsoft.KeyVault/vaults/westuskv1

Name  : CertificateURL
Value : https://westuskv1.vault.azure.net:443/secrets/chackonewcertificate3/c9ca721a5435433f85cadf5feb66ca48 

########  output2 - EastUS cert details

Name  : CertificateThumbprint
Value : C2D7E11DD35153A702A51D10A424A3014B9B6E8B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackoeastuskv/providers/Microsoft.KeyVault/vaults/eastuskv1

Name  : CertificateURL
Value : https://eastuskv1.vault.azure.net:443/secrets/chackonewcertificate2/3e73c6c0d9304ba28508682a66e12cb5

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate2.pfx
dns name - "www.chacko2017.newcertificate.azure.com"
cert Pwd - Password!1


########  output2 - EastUS2 cert details

Name  : CertificateThumbprint
Value : 14BF12E423F7CFFA69F18D69DE80A047C818BD4B

Name  : SourceVault
Value : /subscriptions/33bd304f-367f-4b72-a3ea-7d3576781ceb/resourceGroups/chackoeastus2kv/providers/Microsoft.KeyVault/vaults/eastus2kv1

Name  : CertificateURL
Value : https://eastus2kv1.vault.azure.net:443/secrets/chackonewcertificate1/b91955f2132441b88eb3e8bc4cb8d7ac

Certificate.PFx are in  - C:\MyCertificates\chackonewcertificate1.pfx
dns name - "www.chacko2017.new.certificate.azure.com"
cert Pwd - Password!1

###### AAD values

"azureActiveDirectory": {
  "tenantId":"2f9bd2e7-b4a6-4442-b206-ca7ad0715d97",
  "clusterApplication":"697e29a3-bf43-43c3-9829-c0ac6d800bfc",
  "clientApplication":"48c61eac-97e2-4d4a-89e2-c8cf6d0062d2"
},
