# Create a Service Fabric cluster with OMS 

This template allows you to deploy a secure 1, 3 - 99 node Service Fabric cluster on Standard_D2 sized VMs with Windows Azure Diagnostics turned on. The template also creates an OMS Workspace and a Service Fabric solution within it, and deploys an OMS agent to each of the nodes to collect diagnostics information.

## Creating a custom ARM template

If you are wanting to create a custom ARM template for your cluster, then you have to choices.

1. You can acquire this sample template make changes to it. 
2. Log into the azure portal and use the service fabric portal pages to generate the template for you to customize.
3. Log on to the Azure Portal [http://aka.ms/servicefabricportal](http://aka.ms/servicefabricportal).
4. Go through the process of creating the cluster as described in [Creating Service Fabric Cluster via portal](https://docs.microsoft.com/azure/service-fabric/service-fabric-cluster-creation-via-portal) , but do not click on ***create**, instead go to Summary and download the template and parameters.

## Deploying the ARM template to Azure using Resource Manager PowerShell

Refer to [Deploying ARM templates using ARM PS](https://azure.microsoft.com/documentation/articles/service-fabric-cluster-creation-via-arm/) for detailed guidance on how to. There is detailed guidance on how to set up your certificates as well.


