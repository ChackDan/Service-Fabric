
#++++++++++++++++++++++++++++++Do not run it, it is just so that you know what subscription ID  is which +++++
#Select-AzureRmSubscription -SubscriptionId "33bd304f-367f-4b72-a3ea-7d3576781ceb" #Ignite Subscription
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#             DONOT PRESS F5, THE SCRIPT IS NOT WRITTEN TO SUPPORT IT, USE "RUN SELECTION - F8 "
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


########### Deploy the cluster - secure parms and template
$locName="westus"
$SubID = "33bd304f-367f-4b72-a3ea-7d3576781ceb"

Read-Host "Login on and seclecting the subsciption " $SubIDs " Press enter to continue "

Login-AzureRmAccount
Select-AzureRmSubscription -SubscriptionId $SubID 

#+++++++++++++++++
$certpwd="Password#1234" | ConvertTo-SecureString -AsPlainText -Force
$RDPpwd="Password#1234" | ConvertTo-SecureString -AsPlainText -Force 
$RDPuser="chacko"
$RGname="chackob" 
$clusterloc="westus"
$subname="$RGname.$clusterloc.cloudapp.azure.com"
$templateParmfile= "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\DNS Service Sample\service-fabric-secure-cluster-5-node-1-nodetype-w-DNS-MultiIP\azuredeploy.parameters.json"
$templateFile = "C:\Users\chackdan\Documents\GitHub\Service-Fabric\ARM Templates\DNS Service Sample\service-fabric-secure-cluster-5-node-1-nodetype-w-DNS-MultiIP\5-VM-1-NodeTypes-Secure-WAD.json"
$certfolder="C:\Mycertificates\"


Read-Host "Create a " $numNodes "node cluster in " $clusterloc "and output the cert into " $certfolder ". Press enter to continue "

New-AzureRmServiceFabricCluster -ResourceGroupName $RGname -TemplateFile $templateFile -ParameterFile $templateParmfile -CertificateSubjectName $subname -CertificatePassword $certpwd -CertificateOutputFolder $certfolder -Verbose

########### Connecting to the cluster 
Read-Host " import your certificate to your certificate store. and then Press enter to continue "


Read-Host "connecting to the cluster -   Press enter to continue "

$ClusterName= "$RGname.$clusterloc.cloudapp.azure.com:19000"
$CertThumbprint= "25B367DB613E2C2D1113936D71522E6ACA048C21" 

Connect-serviceFabricCluster -ConnectionEndpoint $ClusterName -KeepAliveIntervalInSec 10 `
    -X509Credential `
    -ServerCertThumbprint $CertThumbprint  `
    -FindType FindByThumbprint `
    -FindValue $CertThumbprint `
    -StoreLocation CurrentUser `
    -StoreName My

##### Get cluster health and other checks
Read-Host "Getting cluser health-   Press enter to continue "

Get-ServiceFabricClusterHealth


