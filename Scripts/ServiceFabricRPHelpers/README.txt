README:


The ServiceFabricRPHelpers.psm1 module provides helper methods  for adding certs to the keyvault for use in the Service Fabric Cluster

1. Goto module directory
2. Import module  
Import-Module .\ServiceFabricRPHelpers.psm1

3. COMMAND NAME
    
    Invoke-AddCertToKeyVault   
SYNTAX
    Invoke-AddCertToKeyVault -SubscriptionId <string> -ResourceGroupName <string> -Location <string> -VaultName <string> -CertificateName <string> -Password <string> -CreateSelfSignedCertificate -DnsName <string> -OutputPath <string>  
    [<CommonParameters>]
    
    Invoke-AddCertToKeyVault -SubscriptionId <string> -ResourceGroupName <string> -Location <string> -VaultName <string> -CertificateName <string> -Password <string> -UseExistingCertificate -ExistingPfxFilePath <string>  [<CommonParameters>]
