#!/usr/bin/python

import re
import os
import sys
import lxml
import boto3
import base64
import getpass
import logging
import requests
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from configparser import ConfigParser

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-east-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '\.aws\credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://fs.spglobal.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)

##########################################################################

# Get the federated credentials from the user
print ('Username:',end=" ")
username = str(input())
password = getpass.getpass()
print ('')

######################
############# Verification Code ##########

print ("MFA Verification Option choice")
print ("Options may vary please verify the list with the login website")
print ('[1] Mobile App Authentication')
print ("[2] Phone Call")
print ("[3] Text Message")
print ("Your Choice:",end=" ")
cho = int(input())
if cho > 3 :
    print ("Wrong Choice choosing default option 1")
    cho = 1
print ("Waiting for authentication......")
print("")
# '[1] verificationOption0 = mobile app authenticate'
# "[2] verificationOption1 = phone call"
# "[3] verificationOption2 = smss"
# "[4] verificationOption3 = mobile app code"
####default
###change to input
verificationOptions = [ "verificationOption0" , "verificationOption1", "verificationOption2"]

verificationOption = verificationOptions[cho-1]

# Initiate session handler

session = requests.Session()

# Programmatically get the SAML assertion
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page

formresponse = session.get(idpentryurl, verify=sslverification)
# Capture the idpauthformsubmiturl, which is the final url after all the 302s

idpauthformsubmiturl = formresponse.url

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
formsoup = BeautifulSoup(formresponse.text,"lxml")
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "user" in name.lower():
        #Make an educated guess that this is the right field for the username
        payload[name] = username
    elif "email" in name.lower():
        #Some IdPs also label the username field as 'email'
        payload[name] = username
    elif "pass" in name.lower():
        #Make an educated guess that this is the right field for the password
        payload[name] = password
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# Set our AuthMethod to Form-based auth because the code above sees two values
# for authMethod and the last one is wrong

payload['AuthMethod'] = 'FormsAuthentication'

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen

# print payload

# Some IdPs don't explicitly set a form action, but if one is set we should
# build the idpauthformsubmiturl by combining the scheme and hostname
# from the entry url with the form action target
# If the action tag doesn't exist, we just stick with the
# idpauthformsubmiturl above

for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

# print idpauthformsubmiturl
# print ''

# Performs the submission of the IdP login form with the above post data

loginresponse = session.post(
    idpauthformsubmiturl, data=payload, verify=sslverification)

# Debug the response if needed
# print (loginresponse.text)

# MFA Step 1 - If you have MFA Enabled, there are two additional steps to authenticate
# Choose a verification option and reload the page

# Capture the idpauthformsubmiturl, which is the final url after all the 302s

mfaurl = loginresponse.url

loginsoup = BeautifulSoup(loginresponse.text,"lxml")
payload2 = {}

for inputtag in loginsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
    payload2[name] = value

# Set mfa auth type here...

payload2['__EVENTTARGET'] = verificationOption
payload2['AuthMethod'] = 'AzureMfaServerAuthentication' ### can change with mfa server can be radius etc

mfaresponse = session.post(
    mfaurl, data=payload2, verify=sslverification)

# Debug the response if needed
# print (mfaresponse.text)

# MFA Step 2 - Fire the form and wait for verification

mfasoup = BeautifulSoup(mfaresponse.text,"lxml")
payload3 = {}

for inputtag in mfasoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
    payload3[name] = value

payload3['AuthMethod'] = 'AzureMfaServerAuthentication'

mfaresponse2 = session.post(
    mfaurl, data=payload3, verify=sslverification)


# # Decode the response and extract the SAML assertion

soup = BeautifulSoup(mfaresponse2.text,'lxml')
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        # (inputtag.get('value'))
        assertion = inputtag.get('value')

# Better error handling is required for production use.
if (assertion == ''):
    #TODO: Insert valid error checking/handling
    print ('Authentication Failed, Please try again')
    sys.exit(0)

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but aws docs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

home = expanduser("~")
filename = home + awsconfigfile

##### Set Proxy ######
if "HTTPS_PROXY" in os.environ:
    print ("Proxy has already been set")
    print ("")
else:
    print("Setting Proxy")
    os.environ["HTTP_PROXY"] = "http://username:password@corp-eq5-proxy.mhc:8080"
    os.environ["HTTPS_PROXY"] = "https://username:password@corp-eq5-proxy.mhc:8080"
# Overwrite and delete the credential variables,  for safety

username = '##############################################'
password = '##############################################'
del username
del password

########## get all accounts tokens ###########

def getalltokens(awsroles):
    # # Read in the existing config file
    config = ConfigParser()
    config.read(filename)
    i = 0
    for awsrole in awsroles:
        if i < len(awsroles):
            role_arn = awsroles[int(i)].split(',')[0]
            principal_arn = awsroles[int(i)].split(',')[1]
            acctname = awsrole.split(',')[0].split(':')[4]+'-'+awsrole.split(',')[0].split(':')[5].split('/')[1]
            client = boto3.client('sts')
            token = client.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)
            # Write the AWS STS token into the AWS credential file
            #print (token)
            access_key = token['Credentials']['AccessKeyId']
            secret_key = token['Credentials']['SecretAccessKey']
            session_token= token['Credentials']['SessionToken']
            expiration = token['Credentials']['Expiration']

            # Put the credentials into a saml specific section instead of clobbering
            # the default credentials
            if not config.has_section(acctname):
                config.add_section(acctname)

            config.set(acctname, 'output', outputformat)
            config.set(acctname, 'region', region)
            config.set(acctname, 'aws_access_key_id', access_key)
            config.set(acctname, 'aws_secret_access_key', secret_key)
            config.set(acctname, 'aws_session_token', session_token)
            i = i+1
    #Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)
    return filename,expiration

##############################################
# If user has more than one role, ask the user which one they want,
# otherwise just proceed
print ("")
if len(awsroles) > 1:
    i = 0
    print ("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print ('[', i+1, ']: ',awsrole.split(',')[0].split(':')[4]+'-'+awsrole.split(',')[0].split(':')[5].split('/')[1])
        i += 1
    print ('[', i+1, ']: Default all accounts')
    print("")
    print ("SELECTION: ",end=" ")
    selectedroleindex = input()
    selectedroleindex = int(selectedroleindex)-1
    # Basic sanity check of input
    if selectedroleindex > len(awsroles) or selectedroleindex < 0:
        print ('You selected an invalid role index, going default')
        selectedroleindex = len(awsroles)
else:
    print ("Only one role found:",awsrole.split(',')[0].split(':')[4]+'-'+awsrole.split(',')[0].split(':')[5].split('/')[1])
    selectedroleindex = 0

####################################################
if selectedroleindex == len(awsroles):
    filename,expiration = getalltokens(awsroles)
    acctname = 'Multiple Accounts'
else:
    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    acctname = awsroles[int(selectedroleindex)].split(',')[0].split(':')[4]+'-'+awsroles[int(selectedroleindex)].split(',')[0].split(':')[5].split('/')[1]
    # Use the assertion to get an AWS STS token using Assume Role with SAML
    client = boto3.client('sts')
    token = client.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)
    ## debug
    #print (token)
    # print (token.keys())
    # print (token.values())

    # Write the AWS STS token into the AWS credential file
    access_key = token['Credentials']['AccessKeyId']
    secret_key = token['Credentials']['SecretAccessKey']
    session_token= token['Credentials']['SessionToken']
    expiration = token['Credentials']['Expiration']

    # # Read in the existing config file
    config = ConfigParser()
    config.read(filename)

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(acctname):
        config.add_section(acctname)

    config.set(acctname, 'output', outputformat)
    config.set(acctname, 'region', region)
    config.set(acctname, 'aws_access_key_id', access_key)
    config.set(acctname, 'aws_secret_access_key', secret_key)
    config.set(acctname, 'aws_session_token', session_token)
    #Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

# Give the user some basic info as to what has just happened
print ('\n\n----------------------------------------------------------------')
print ('Your new access key pair has been stored in the AWS configuration file {0} under the profile {1}.'.format(filename,acctname))
print ('Note that it will expire at UTC {0}.'.format(expiration))
print ('After this time, you may safely rerun this script to refresh your access key pair.')
print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile default ec2 describe-instances).')
print ('----------------------------------------------------------------\n\n')

input("Press enter to exit")
##################### END ###########################
