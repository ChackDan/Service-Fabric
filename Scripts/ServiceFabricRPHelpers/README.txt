README:

This module provides helper methods for deploying and upgrading ServiceFabric clusters

1. Goto module directory
2. Import module  
Import-Module .\ServiceFabricRPHelpers.psm1

3. COMMAND NAME
    Invoke-ServiceFabricRPClusterScaleUpgrade    
SYNTAX
    Invoke-ServiceFabricRPClusterScaleUpgrade [-ResourceGroupName] <string> [-SubscriptionId] <string> [[-PerformAction] <bool>]  [<CommonParameters>]
    
    Invoke-AddCertToKeyVault   
SYNTAX
    Invoke-AddCertToKeyVault -SubscriptionId <string> -ResourceGroupName <string> -Location <string> -VaultName <string> -CertificateName <string> -Password <string> -CreateSelfSignedCertificate -DnsName <string> -OutputPath <string>  
    [<CommonParameters>]
    
    Invoke-AddCertToKeyVault -SubscriptionId <string> -ResourceGroupName <string> -Location <string> -VaultName <string> -CertificateName <string> -Password <string> -UseExistingCertificate -ExistingPfxFilePath <string>  [<CommonParameters>]
