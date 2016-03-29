
# Introduction

This is a public repo that I use to share out PowerShell Modules, ARM templates and other helpful documents, that I have had customers ask me for and the ones that I have personally found to be very helpful with using [Microsoft Azure service fabric](http://aka.ms/servicefabric) 


# Microsoft Azure Service Fabric Helper PowerShell module
You can find ServiceFabricRPHelper module under the **Scripts** folder.
 
This PowerShell module allows you to do two things easily. The ReadMe.txt file in that folder explains the syntax.

1) Create and upload a certificate to azure Key Vault : For detailed instructions, refer to [Service Fabric Security](http://go.microsoft.com/fwlink/?LinkID=708324&clcid=0x409)

<!--2) Add/remove VMs from a Service Fabric Cluster - For detailed instructions, refer to [Service Fabric cluster Scale up or down](http://go.microsoft.com/fwlink/?LinkID=708408&clcid=0x409)-->

# Microsoft Azure Service Fabric ARM templates

This repository contains templates that you can use to deploy Microsoft Azure Service Fabric Clusters into Microsoft Azure. I have posted two of these templates to the azure template gallery as well. 

If you are wanting to create a custom ARM template for your cluster, then you have to choices.

1. You can acquire this sample template make changes to it. 
2. Log into the azure portal and use the service fabric portal pages to generate the template for you to customize. 
	3. Log on to the Azure Portal [http://aka.ms/servicefabricportal](http://aka.ms/servicefabricportal).
	2. Go through the process of creating the cluster as described in [Creating Service Fabric Cluster via portal](https://azure.microsoft.com/documentation/articles/service-fabric-cluster-creation-via-portal) , but do not click on ***OK**, instead go to Summary and download the template.
	
	 	![DownloadTemplate][DownloadTemplate]


	3. you can save the downloaded template to your local machine, make any changes you need and deploy to azure.

Refer to [Deploying ARM templates using PS ](https://azure.microsoft.com/en-us/documentation/articles/resource-group-template-deploy/) if you need guidance on how to.

<!--Image references-->
[DownloadTemplate]: ./media/DownloadTemplate.png