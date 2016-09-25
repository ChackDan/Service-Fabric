Usage HELP content 

./cert_helper.py -h
usage: cert_helper.py [-h] {pem,pfx,ss} ...

positional arguments:
  {pem,pfx,ss}  commands
    pem         pfx input file commands
    pfx         pem input file commands
    ss          self sign certificate commands



#pem help 

./cert_helper.py pem -h
usage: cert_helper.py pem [-h] [-ifile INPUT_CERT_FILE] [-sub SUBSCRIPTION_ID]
                          [-rgname RESOURCE_GROUP_NAME] [-kv KEY_VAULT_NAME]
                          [-sname CERTIFICATE_NAME] [-l LOCATION]
                          [-p PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  -ifile INPUT_CERT_FILE, --input_cert_file INPUT_CERT_FILE
                        Input certificate file
  -sub SUBSCRIPTION_ID, --subscription_id SUBSCRIPTION_ID
                        Path to subscription
  -rgname RESOURCE_GROUP_NAME, --resource_group_name RESOURCE_GROUP_NAME
                        name of resource group
  -kv KEY_VAULT_NAME, --key_vault_name KEY_VAULT_NAME
                        Key vault name
  -sname CERTIFICATE_NAME, --certificate_name CERTIFICATE_NAME
                        Name for secret
  -l LOCATION, --location LOCATION
                        Location
  -p PASSWORD, --password PASSWORD
                        password for certificate

# pfx help 

./cert_helper.py pfx -h
usage: cert_helper.py pfx [-h] [-ifile INPUT_CERT_FILE] [-sub SUBSCRIPTION_ID]
                          [-rgname RESOURCE_GROUP_NAME] [-kv KEY_VAULT_NAME]
                          [-sname CERTIFICATE_NAME] [-l LOCATION]
                          [-p PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  -ifile INPUT_CERT_FILE, --input_cert_file INPUT_CERT_FILE
                        Input certificate file
  -sub SUBSCRIPTION_ID, --subscription_id SUBSCRIPTION_ID
                        Path to subscription
  -rgname RESOURCE_GROUP_NAME, --resource_group_name RESOURCE_GROUP_NAME
                        name of resource group
  -kv KEY_VAULT_NAME, --key_vault_name KEY_VAULT_NAME
                        Key vault name
  -sname CERTIFICATE_NAME, --certificate_name CERTIFICATE_NAME
                        Name for secret
  -l LOCATION, --location LOCATION
                        Location
  -p PASSWORD, --password PASSWORD
                        password for certificate

# self signed help 
./cert_helper.py ss -h
usage: cert_helper.py ss [-h] [-subj SUBJECTNAME] [-sub SUBSCRIPTION_ID]
                         [-rgname RESOURCE_GROUP_NAME] [-kv KEY_VAULT_NAME]
                         [-sname CERTIFICATE_NAME] [-l LOCATION] [-p PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  -subj SUBJECTNAME, --subjectname SUBJECTNAME
                        subject name for self sign certificate
  -sub SUBSCRIPTION_ID, --subscription_id SUBSCRIPTION_ID
                        Path to subscription
  -rgname RESOURCE_GROUP_NAME, --resource_group_name RESOURCE_GROUP_NAME
                        name of resource group
  -kv KEY_VAULT_NAME, --key_vault_name KEY_VAULT_NAME
                        Key vault name
  -sname CERTIFICATE_NAME, --certificate_name CERTIFICATE_NAME
                        Name for secret
  -l LOCATION, --location LOCATION
                        Location
  -p PASSWORD, --password PASSWORD
                        password for certificate
