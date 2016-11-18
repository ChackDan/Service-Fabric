#!/usr/bin/env python
from __future__ import print_function

import argparse
import base64
import json

def formatCertificateToKeyvaultSecret(args):
	f = open(args.cert_file, 'rb')
	try:
		ba = bytearray(f.read())
		cert_base64 = base64.b64encode(ba)
		json_blob = {
			'data': cert_base64,
			'dataType': 'pfx',
			'password': args.password
		}
		blob_data = json.dumps(json_blob)
		content_bytes = bytearray(blob_data)
		content = base64.b64encode(content_bytes)
		return content
	finally:
		f.close()

def main():
	parser = argparse.ArgumentParser()
	
	subparsers = parser.add_subparsers()
	
	formatCertSecretParser = subparsers.add_parser('format-secret', help='Formats the certificate into the expected format for service fabric, normally followed by uploading this to keyvault')
	formatCertSecretParser.add_argument('-c', '--pkcs12-cert', dest='cert_file', required=True, help='The pkcs12 cert that you want to format as a secret for Service Fabric Keyvault')
	formatCertSecretParser.add_argument('-p', '--password', dest='password', required=True, help='The password for the certificate')
	formatCertSecretParser.set_defaults(func=formatCertificateToKeyvaultSecret)
	
	args = parser.parse_args()
	print(args.func(args))

if __name__ == "__main__":
	main()