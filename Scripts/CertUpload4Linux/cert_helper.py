#!/usr/bin/python
import os
import base64
import json
import sys
import logging
import logging.handlers
import subprocess
import time
import re
import argparse


operation = "keyvault_helper_module"
script_path = os.path.realpath(__file__)
script_directory = os.path.dirname(script_path)
log_path = os.path.join(script_directory, '{0}.log'.format(operation))
log_level = logging.DEBUG
resolve_lock_err_cmd =""

class OperationFailed(Exception):

    def __init__(self, operation, message):
        self.operation = operation
        self.message = message





def get_logger(logger_name, logger_path, log_level):
    '''Returns a properly formatted logger object that uses a rotating file handler'''
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    logFormatter = logging.Formatter('%(asctime)s [%(levelname)s] - %(message)s')

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(log_level)
    consoleHandler.setFormatter(logFormatter)

    fileHandler = logging.handlers.RotatingFileHandler(logger_path, maxBytes=1024 * 1024, backupCount=2)
    fileHandler.setLevel(log_level)
    fileHandler.setFormatter(logFormatter)

    logger.addHandler(consoleHandler)
    logger.addHandler(fileHandler)

    return logger


log = get_logger(operation, log_path, log_level)


def execute_command(command_list, raise_exception_on_error=True, available_retry=1, verbose=False):
    '''Executes the specified command using the supplied parameters'''
    status = 1
    retrycount = 0
    while (status != 0 and retrycount < available_retry):
        try:
            process = subprocess.Popen(command_list, bufsize=4096, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       shell=True)

            while process.poll() is None:
                time.sleep(10)

        except OSError as os_err:
            log.error('{0}:{1}'.format(os_err.errno, os_err.strerror))
            process.kill()
        except ValueError:
            log.error('Invalid arguments:{0}'.format(command_list))
            time.sleep(30)
            process.kill()
        except IOError as io_err:
            log.error("IO Error: {0}:{1}".format(io_err.errno, io_err.strerror))
            if "dpkg: error: dpkg status database is locked by another process" in e.strerror:
                process.kill()
        except Exception as e:
            log.error("Unexpected error:{0}".format(sys.exc_info()[0]))
            log.error("error msg: {0}".format(e.message))
            process.kill()
        finally:
            output, error = process.communicate()
            status = process.returncode

            if verbose:
                log.debug(
                    'Command List: {0}{1}Status: {2}{1}Output: {3}{1}Error: {4}{1}'.format(command_list, os.linesep, status,
                                                                                           output.strip(),
                                                                                           error.strip()))

            retrycount += 1

            if status != 0:
                log.error(
                    'Command List: {0}{1}Status: {2}{1}Output: {3}{1}Error: {4}{1}'.format(command_list, os.linesep,
                                                                                           status, output.strip(),
                                                                                           error.strip()))

                if "Could not get lock /var/lib/dpkg/lock" in error:
                    execute_command([resolve_lock_err_cmd], available_retry=3)

    return status, output, error

class Result(object):
    success = False
    error_code = 0
    error_msg = ""
    data = None
    info_msg = ""

    def __init__(self, success=True, error_msg="", info_msg="", data={}):
        self.success = success
        self.error_msg = error_msg
        self.info_msg = info_msg
        self.data = data

    def setSuccess(self, success):
        self.success = success

    def IsSuccess(self):
        return self.success

    def setErrorMessage(self, error_msg):
        self.error_msg += error_msg +'\n'
        if self.success:
            self.success = False

    def getErrorMessage(self):
        return self.error_msg

    def setInfoMessage(self, info_msg):
        self.info_msg += info_msg + '\n'

    def getInfoMessage(self):
        return self.info_msg

    def addData(self, name, value):
        self.data[name] = value

    def getData(self):
        return self.data

    def toString(self):
        return "Info:\n{0}\nData:\n{1} Error:\n{0}".format(self.info_msg, self.data, self.error_msg)


def parse_output(output):
    result = Result()
    error_token = "error".encode('utf-8')
    info_token = "info".encode('utf-8')
    data_token = "data".encode('utf-8')

    output_lines = output.splitlines()
    num_lines_in_parsed_output = len(output_lines)
    result.setSuccess(True)
    for index in range(0, num_lines_in_parsed_output):

            line_info = output_lines[index].decode('utf-8').split()

            first_token = line_info[0].rstrip(':').encode('utf-8')

            if error_token in first_token:
                    result.setErrorMessage(output_lines[index].lstrip("error:").encode('utf-8'))

            #TODO: Change this to use regex to collect data accurately
            elif data_token in first_token:
                    data_pattern = re.compile('(data:)')
                    searchStr = output_lines[index].encode('utf-8')

                    if "id" in searchStr:
                        value_pattern = re.compile(r'"([^"]*)"')
                        value_result = re.search(value_pattern, searchStr)
                        if value_result:
                            result.addData("id", value_result.groups()[0])

            elif info_token in first_token:
                    result.setErrorMessage(output_lines[index].lstrip("error:").encode('utf-8'))

    return  result


def parse_result(output, error):
    p_output = parse_output(output=output)
    p_error = parse_output(output=error)

    return Result(p_error.IsSuccess(), p_error.getErrorMessage(), p_output.getInfoMessage(), p_output.getData())


def set_subscription(subscription_id):
    set_azure_subscription = "azure account set {0}".format(subscription_id)
    return_error_code = 0

    status, output, error = execute_command(set_azure_subscription)

    parsed_result = parse_result(output,error)
    parsed_result.error_code = status

    if not parsed_result.IsSuccess():
        raise OperationFailed(set_azure_subscription, parsed_result.getErrorMessage())


def create_resource_group(resource_group_name, region):

    create_resource_group = "azure group create '{0}' '{1}'".format(resource_group_name, region)
    return_error_code = 0

    status, output, error = execute_command(create_resource_group)

    parsed_result = parse_result(output,error)
    parsed_result.error_code = status

    if not parsed_result.IsSuccess():
        raise OperationFailed(create_resource_group, parsed_result.getErrorMessage())


def create_key_vault(keyvault_name, resource_group_name, region):
    create_keyvault = "azure keyvault create --vault-name '{0}' --resource-group '{1}' --location '{2}'".format(keyvault_name, resource_group_name, region)
    show_keyvault = "azure keyvault show --vault-name '{0}'".format(keyvault_name)

    status, output, error = execute_command(create_keyvault)

    parsed_result = parse_result(output, error)
    parsed_result.error_code = status

    if not parsed_result.success:
        kv_exists_pattern = re.compile('\s[vV]ault\s[\w\d]+\salready\sexists\s.*?')
        kv_exists_result =  re.search(kv_exists_pattern, parsed_result.error_msg)

        if(kv_exists_result):
            parsed_result.setSuccess(True)
            status1, output1, error1 = execute_command(show_keyvault)
            show_parsed_result = parse_result(output1, error1)
            parsed_result.error_code = status1

            return parsed_result.data["id"]

        else:
            raise OperationFailed(create_keyvault, parsed_result.error_msg)

    return parsed_result.data["id"]



def upload_secret(resource_group_name, region, keyvault_name,  secret, subscription, certificate_name):

    set_keyvault_secret = "azure keyvault secret set --vault-name '{0}' --secret-name '{1}' --value '{2}'".format(keyvault_name, certificate_name, secret)
    enable_keyvault_for_deployment = "azure keyvault set-policy --vault-name '{0}' --enabled-for-deployment {1} --enabled-for-template-deployment {1}".format(keyvault_name, "true")

    status, output, error = execute_command(set_keyvault_secret)

    sourceurl_result = parse_result(output, error)
    sourceurl_result.error_code = status

    sourceurl = sourceurl_result.data["id"]

    if not sourceurl_result.IsSuccess():
        raise OperationFailed(set_keyvault_secret, sourceurl_result.error_msg)

    status2, output2, error2 = execute_command(enable_keyvault_for_deployment)
    parsed_result = parse_result(output2, error2)
    parsed_result.error_code = status2

    if 0 != status2:
        raise OperationFailed(enable_keyvault_for_deployment, error2)

    return sourceurl

def get_certificate_content(certificate_path):
    fh = open('sfrptestautomation.pfx', 'rb')
    try:
        ba = bytearray(fh.read())
        cert_base64_str = base64.b64encode(ba)
        password = 'test'
        json_blob = {
            'data': cert_base64_str,
            'dataType': 'pfx',
            'password': password
        }

        blob_data= json.dumps(json_blob)
        content_bytes= bytearray(blob_data)
        content = base64.b64encode(content_bytes)

        return content

    finally:
        fh.close

    fh.close()

def get_file_name(file_path):
    base = os.path.basename(file_path)
    return os.path.splitext(base)[0]

class Certificate(object):

    pem_file_path=""
    pfx_file_path=""

    def __init__(self, subscription_id, rg_name, kv_name, location, certificate_name, password, pfx_file_path="", pem_file_path=""):
        self.subscription_id = subscription_id
        self.rg_name = rg_name
        self.kv_name = kv_name
        self.location = location
        self.certificate_name = certificate_name
        self.pfx_file_path = pfx_file_path
        self.pem_file_path = pem_file_path
        self.password = password


    def getPfxFilePath(self):
        return self.pfx_file_path

    def getResourceGroupName(self):
        return self.rg_name

    def getKeyVaultName(self):
        return self.kv_name

    def getLocation(self):
        return self.location

    def getSubscription(self):
        return self.subscription_id

    def getCertificateName(self):
        return self.certificate_name

    def getPassword(self):
        return self.password

    def manupulate_cert(self):
        raise NotImplementedError("Subclass must implement")

    def cleanup(self):
        raise NotImplementedError("Subclass must implement")

    def getContent(self):
        fh = open(self.getPfxFilePath(), 'rb')
        try:
            ba = bytearray(fh.read())
            cert_base64_str = base64.b64encode(ba)
            password = self.getPassword()
            json_blob = {
                'data': cert_base64_str,
                'dataType': 'pfx',
                'password': password
            }
            blob_data= json.dumps(json_blob)
            content_bytes= bytearray(blob_data)
            content = base64.b64encode(content_bytes)
            return content
        finally:
            fh.close
        fh.close()

    def extract_thumbprint(self):
        get_thumbprint = "openssl x509 -in {0} -noout -fingerprint".format(self.pem_file_path)
        status, output, error = execute_command(get_thumbprint)
        if (status != 0):
            print "Error: {0}".format(error)
        else:
            pattern = re.compile('Fingerprint=([\w\W\d\D]+)')
            thumbprint  = re.search(pattern, output)

            return (thumbprint.groups()[0]).encode('utf-8').replace(":", "")

        return ""



    def upload_cert(self):
        self.manupulate_cert()
        set_subscription(subscription_id=self.subscription_id)
        rg_result = create_resource_group(self.rg_name, self.location)
        kv_result = create_key_vault(self.kv_name, self.rg_name, self.location)
        secret_result = upload_secret(self.rg_name, self.location, self.kv_name, self.getContent(), self.subscription_id, self.certificate_name)
        thumbprint = self.extract_thumbprint()
        self.cleanup()

        return thumbprint, kv_result, secret_result

class pfx_certificate_format(Certificate):
    def manupulate_cert(self):
        file_name = get_file_name(self.pfx_file_path)
        self.tmp_file_path = "/tmp/{0}.pem".format(file_name)
        prepare_pem_file = "openssl pkcs12 -in {0} -out {1} -nodes -passin pass:'{2}'".format(self.pfx_file_path, self.tmp_file_path, self.password)
        status, output, error = execute_command(prepare_pem_file)
        if(status != 0):
            print error
        else:
            self.pem_file_path = self.tmp_file_path

    def cleanup(self):
        rm_tmp_pem = "rm {0}".format(self.tmp_file_path)
        status, output, error = execute_command(rm_tmp_pem)
        if (status != 0):
            print error

class pem_certificate_format(Certificate):
    def manupulate_cert(self):
        file_name = get_file_name(self.pem_file_path)
        self.tmp_file_path = "/tmp/{0}.pfx".format(file_name)
        prepare_pfx_file = "openssl pkcs12 -export -out {1} -inkey {0} -in {0} -passout pass:'{2}'".format(self.pem_file_path, self.tmp_file_path, self.password)
        status, output, error = execute_command(prepare_pfx_file)
        if (status != 0):
            print error
            raise OperationFailed("creation of temp pfx failed with error {0}".format(error))
        else:
            self.pfx_file_path = self.tmp_file_path

    def cleanup(self):
        rm_tmp_pem = "rm {0}".format(self.tmp_file_path)
        status, output, error = execute_command(rm_tmp_pem)
        if (status != 0):
            print error

def cert_factory(input_params):
    if ("pem" in input_params["cert_type"] and "pfx" in input_params["cert_type"]):
        print 'invoke_add_cert.py --ifile <inputcertfile> --resourcegroup <rgname> --keyvault <keyvaultname> --subscriptionid <subscription> --certificatename <certificatename> --location <region> --certtype pem|pfx'
        sys.exit()
    elif "pem" in input_params["cert_type"]:
        return  pem_certificate_format( subscription_id= input_params["subscription_id"],
                                        rg_name= input_params["resource_groupname"],
                                        pem_file_path=input_params["cert_file"],
                                        kv_name=input_params["keyvault_name"],
                                        location=input_params["location"],
                                        certificate_name=input_params["certificate_name"])
    elif "pfx" in input_params["cert_type"]:
        return pfx_certificate_format(subscription_id= input_params["subscription_id"],
                                        rg_name= input_params["resource_groupname"],
                                        pfx_file_path=input_params["cert_file"],
                                        kv_name=input_params["keyvault_name"],
                                        location=input_params["location"],
                                        certificate_name=input_params["certificate_name"])
    elif "self_sign" in input_params["cert_type"]:
        return  pem_certificate_format( subscription_id= input_params["subscription_id"],
                                        rg_name= input_params["resource_groupname"],
                                        pem_file_path=input_params["cert_file"],
                                        kv_name=input_params["keyvault_name"],
                                        location=input_params["location"],
                                        certificate_name=input_params["certificate_name"])

def prepare_self_sign_certificate(subject, certificate_name):
    certificate_file = '/tmp/{0}.pem'.format(certificate_name)
    create_certificate= 'openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {0} -out {0} -subj "/CN={1}"'.format(certificate_file, subject)
    status, output, error = execute_command(create_certificate)

    parsed_result = parse_result(output, error)
    parsed_result.error_code = status

    if not parsed_result.IsSuccess():
        raise OperationFailed(create_resource_group, parsed_result.getErrorMessage())

    return certificate_file

def verify_required_params(args):
    if not args.subscription_id:
        print ("subscription id is required")
        sys.exit()
    if not args.resource_group_name:
        print ("resource group name is required")
        sys.exit()
    if not args.key_vault_name:
        print ("key vault name is required")
        sys.exit()
    if not args.location:
        print ("location is required")
        sys.exit()

    if not args.certificate_name:
        print ("certificate name  is required")
        sys.exit()

    if not args.password:
        print ("password is required")
        sys.exit()

def cert_factory(args):

    verify_required_params(args)

    if("ss" in args.which):
        if (args.subjectname and args.certificate_name):
            cert_file = prepare_self_sign_certificate(args.subjectname, args.certificate_name)
            return pem_certificate_format(subscription_id=args.subscription_id,
                                      rg_name=args.resource_group_name,
                                      pem_file_path=cert_file,
                                      kv_name=args.key_vault_name,
                                      location=args.location,
                                      certificate_name=args.certificate_name,
                                      password=args.password)
        else:
            print ("selfsign flag cannot be passed witout subjectname and certificatename")
            sys.exit()

    if ("pem" in args.which and "pfx" in args.which):
        if not (args.input_cert_file):
            print "input certificate file path is required"
        sys.exit()
    if "pem" in args.which:
        return  pem_certificate_format( subscription_id= args.subscription_id,
                                        rg_name= args.resource_group_name,
                                        pem_file_path=args.input_cert_file,
                                        kv_name=args.key_vault_name,
                                        location=args.location,
                                        certificate_name=args.certificate_name,
                                        password=args.password)
    elif "pfx" in args.which:
        return pfx_certificate_format(subscription_id= args.subscription_id,
                                        rg_name= args.resource_group_name,
                                        pfx_file_path=args.input_cert_file,
                                        kv_name=args.key_vault_name,
                                        location=args.location,
                                        certificate_name=args.certificate_name,
                                        password=args.password)



def get_arg_parser():
    '''Returns an argument parser suitable for interpreting the specified command line arguments'''

    arg_parser = argparse.ArgumentParser()

    subparsers = arg_parser.add_subparsers(help='commands')
    pem_parser =subparsers.add_parser('pem', help='pfx input file commands')
    pem_parser.set_defaults(which="pem")
    pfx_parser = subparsers.add_parser('pfx', help='pem input file commands')
    pfx_parser.set_defaults(which="pfx")
    ss_parser =subparsers.add_parser('ss', help='self sign certificate commands')
    ss_parser.set_defaults(which="ss")

    # pem and pfx required file
    pem_parser.add_argument('-ifile', '--input_cert_file', action = 'store', help = 'Input certificate file')
    pem_parser.add_argument('-sub', '--subscription_id', action='store', help='Path to subscription')
    pem_parser.add_argument('-rgname', '--resource_group_name', action='store', help='name of resource group')
    pem_parser.add_argument('-kv', '--key_vault_name', action='store', help='Key vault name')
    pem_parser.add_argument('-sname', '--certificate_name', action='store', help='Name for secret')
    pem_parser.add_argument('-l', '--location', action='store', help='Location')
    pem_parser.add_argument('-p', '--password', action='store', help='password for certificate')

    pfx_parser.add_argument('-ifile', '--input_cert_file', action = 'store', help = 'Input certificate file')
    pfx_parser.add_argument('-sub', '--subscription_id', action='store', help='Path to subscription')
    pfx_parser.add_argument('-rgname', '--resource_group_name', action='store', help='name of resource group')
    pfx_parser.add_argument('-kv', '--key_vault_name', action='store', help='Key vault name')
    pfx_parser.add_argument('-sname', '--certificate_name', action='store', help='Name for secret')
    pfx_parser.add_argument('-l', '--location', action='store', help='Location')
    pfx_parser.add_argument('-p', '--password', action='store', help='password for certificate')

    # subj name only required for self sign certificate
    ss_parser.add_argument('-subj', '--subjectname', action='store', help='subject name for self sign certificate')
    ss_parser.add_argument('-sub', '--subscription_id', action='store', help='Path to subscription')
    ss_parser.add_argument('-rgname', '--resource_group_name', action='store', help='name of resource group')
    ss_parser.add_argument('-kv', '--key_vault_name', action='store', help='Key vault name')
    ss_parser.add_argument('-sname', '--certificate_name', action='store', help='Name for secret')
    ss_parser.add_argument('-l', '--location', action='store', help='Location')
    ss_parser.add_argument('-p', '--password', action='store', help='password for certificate')

    return arg_parser

def main():

    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()
    cert = cert_factory(args)

    thumbprint, resourceid, secreturl = cert.upload_cert()
    if("ss" in args.which):
        print "Please copy self signed cert from : {0}".format(cert.pem_file_path)
    print("SourceVault: {1}\nCertificateUrl: {2}\nCertificateThumbprint: {0}\n".format(thumbprint, resourceid, secreturl))


if __name__ == "__main__":
    main()
