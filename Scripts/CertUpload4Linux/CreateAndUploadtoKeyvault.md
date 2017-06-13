# Introduction

In ARM templates, when configuring the deployment of Service Fabric clusters and using certificate management, you must upload a certificate to a keyvault secret and then specify in the template where to find the certificate. This document describes the component pieces to make this work in a linux environment.

## Generating the Certificate

To generate the cert we use openssl:
```
password="$(openssl rand -base64 32)"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=example.com"
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -passout pass:"$password"
```

## Uploading certificate to keyvault

To upload the certificate to keyvault we must first format the certificate and add additional data to it so that Service Fabric knows how to use it. The format is a base64 encoded json blob containing the following keys: 'data', 'dataType' and 'password'. Data should be the base64 encoded byte array of the PFX file.
A script has been provided that properly encodes the PFX file to be uploaded to Keyvault.
```
formatted_secret=$(./servicefabric.py format-secret --pkcs12-cert server.pfx --password $password)
```

After formatting the secret you can upload as normal to keyvault using the Azure CLI or any other method.
```
azure keyvault secret set <your-vault-name> <your-secret-name> -w $formatted_secret
```

**Note: Your keyvault will need to have the flags `enable-for-deployment` and `enable-for-template-deployment` set to deploy using this certificate.

## Template File Settings

There are three pieces of information you will need to provide in your template file to use this certificate: the certificate thumbprint, the secret's url, and the keyvault resource Id.

Certificate Thumbprint:
```
CERT_THUMB=$(openssl x509 -in server.crt -noout -fingerprint | awk -F= '{print $NF}' | sed -e 's/://g')
```

Secret's URL:
```
SECRET_URL=$(azure keyvault secret show <your-vault-name> <your-secret-name> --json | python -c 'import json,sys;print json.load(sys.stdin)["id"]')
```

Keyvault Resource Id:
```
KEYVAULTID=$(azure keyvault show <your-vault-name> --json | python -c 'import json,sys;print json.load(sys.stdin)["id"]')
```

### Where they are used

There are two resources that will need some of the information generated above: the VMs and the Service Fabric cluster itself.

The VMs that will be used in the Service Fabric cluster should have a VM extension published by `Microsoft.Azure.ServiceFabric`. In this extension set the property value of `properties.settings.certificate` to:
```
{
  "thumbprint": "<your-certificate-thumbprint-here>",
  "x509StoreName": "My"
}
```

The VM will also need in the `osProfile.secrets` property the value of:
```
[{
  "sourceVault": {
    "id": "<your-keyvault-id-here>"
  },
  "vaultCertificates": [{
    "certificateUrl": "<your-secrets-url-here>",
    "certificateStore": "My"
  }]
}]
```

The Service Fabric cluster resource will need the property `properties.certificate` set to:
```
{
  "thumbprint": "<your-certificate-thumbprint-here>",
  "x509StoreName": "My"
}
```
