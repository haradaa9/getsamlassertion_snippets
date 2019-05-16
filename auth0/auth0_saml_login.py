#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import json
import re
import base64
import urllib.request
import urllib.error
import urllib.parse
import time
import html.parser

# Parameters
URL="" # Auth0 AWS login URL
USERNAME=""
PASSWORD=""

# Calculated parameters
TENANT=URL.split("//")[1].split(".")[0]
CLIENT_ID=URL.split("/")[-1]

# Constants
AUTH0_CLIENT_INFO="""{"name":"lock.js","version":"11.11.0","lib_version":{"raw":"9.8.1"}}"""
AUTH0_CLIENT_HEADER=base64.b64encode(AUTH0_CLIENT_INFO.encode())

class FormParser(html.parser.HTMLParser):
    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.flags_inside_form = False
        self.action = None
        self.method = None
        self.fields = []

    def handle_starttag(self, tag, attributes):
        attributes_map = dict(attributes)
        if tag == "form":
            self.flags_inside_form = True
            self.action = attributes_map["action"]
            self.method = attributes_map["method"]
        elif tag == "input" and self.flags_inside_form and "name" in attributes_map:
            self.fields.append((attributes_map["name"], attributes_map["value"]))

    def handle_endtag(self, tag):
        if tag == "form":
            self.flags_inside_form = False

def get_login_info(opener):
    """
    access url => redirect => get parameters from json in html
    """
    request = urllib.request.Request(URL)
    response = opener.open(request)
    html = response.read().decode()
    # print(html)

    params_base64 = re.search("window.atob\('(.+?)'\)", html).group(1)
    params = json.loads(base64.b64decode(params_base64).decode())
    # print(params)

    return params

def get_connection_name():
    """
    get connection list from json in javascript => choose connection
    """
    request = urllib.request.Request("https://cdn.auth0.com/client/%s.js"%CLIENT_ID)
    response = urllib.request.urlopen(request)
    javascript = response.read().decode()
    # print(javascript)

    client_info = json.loads(re.search("Auth0.setClient\((.*)\)", javascript).group(1))
    # print(client_info)

    connection_names = []
    for strategy in client_info["strategies"]:
        for connection in strategy["connections"]:
            connection_names.append(connection["name"])
    # print(connection_names)

    if len(connection_names) == 0:
        raise RuntimeError("No connection available")
    elif len(connection_names) == 1:
        connection_name = connection_names[0]
    else:
        print("Please enter the index of connection that contains your account:")
        for index, name in enumerate(connection_names):
            print("%d: %s"%(index+1, name))
        index = int(input("index: "))-1
        connection_name = connection_names[index]
    print("Use connection: %s"%(connection_name))
    return connection_name

def do_login(opener, login_info, connection_name, username, password):
    """
    post json to /usernamepassword/login => get a form =>
    post the form => get mfa parameters from html
    """
    login_payload = {
        "client_id": CLIENT_ID,
        "connection": connection_name,
        "password": password,
        "popup_options": "{}",
        "protocol": "samlp",
        "redirect_uri": "https://signin.aws.amazon.com/saml",
        "response_type": "code",
        "scope": "openid profile email",
        "sso": True,
        "state": login_info["state"],
        "tenant": TENANT,
        "username": username,
        "_csrf": login_info["_csrf"],
        "_intstate": "deprecated"
    }
    login_payload_json = json.dumps(login_payload).encode()
    # print(login_payload)

    headers = {
        "Content-Type": "application/json",
        "Origin": "https://%s.auth0.com"%TENANT,
        "Auth0-Client": AUTH0_CLIENT_HEADER
    }
    request = urllib.request.Request(
        "https://%s.auth0.com/usernamepassword/login"%TENANT,
        data=login_payload_json,
        method="POST",
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Login error: %s"%error) from None
    # print(result)

    # if success we will get a form in html, post it
    parser = FormParser()
    parser.feed(result)
    callback_params = urllib.parse.urlencode(parser.fields).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://%s.auth0.com"%TENANT
    }
    request = urllib.request.Request(
        parser.action,
        data=callback_params,
        method=parser.method.upper(), # post => POST
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Login callback error: %s"%error) from None
    # print(result)

    mfa_info = {
        "mfaServerUrl": re.search("mfaServerUrl:\s*?\"(.+?)\"", result).group(1),
        "requestToken": re.search("requestToken:\s*?\"(.+?)\"", result).group(1),
        "postActionURL": re.search("postActionURL:\s*?\"(.+?)\"", result).group(1),
        "globalTrackingId": re.search("globalTrackingId:\s*?\"(.+?)\"", result).group(1),
    }
    # print(mfa_info)

    return mfa_info

def do_mfa_verify(mfa_info):
    """
    call /api/start-flow => get transaction token from json result =>
    ask verification code => call /api/verify-otp => 204 means success =>
    call /api/transaction-state => get mfa result from json result

    also see: https://github.com/auth0/auth0-guardian.js/blob/master/lib/utils/polling_client.js
    """
    headers = {
        "Content-Type": "application/json",
        "Origin": "https://%s.auth0.com"%TENANT,
        "Authorization": "Bearer %s"%mfa_info["requestToken"],
        "x-global-tracking-id": mfa_info["globalTrackingId"]
    }
    request = urllib.request.Request(
        "%s/api/start-flow"%mfa_info["mfaServerUrl"],
        data=json.dumps({ "state_transport": "polling" }).encode(),
        method="POST",
        headers=headers)
    try:
        response = urllib.request.urlopen(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("MFA start flow error: %s"%error) from None
    mfa_flow_info = json.loads(result)
    mfa_transaction_token = mfa_flow_info["transaction_token"]
    # print(mfa_flow_info)
    # print(mfa_transaction_token)

    mfa_code = input("Please enter your MFA verification code: ")
    mfa_payload = {
        "code": mfa_code,
        "type": "manual_input"
    }
    mfa_payload_json = json.dumps(mfa_payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Origin": "https://%s.auth0.com"%TENANT,
        "Authorization": "Bearer %s"%mfa_transaction_token,
        "x-global-tracking-id": mfa_info["globalTrackingId"]
    }
    request = urllib.request.Request(
        "%s/api/verify-otp"%mfa_info["mfaServerUrl"],
        data=mfa_payload_json,
        method="POST",
        headers=headers)
    try:
        response = urllib.request.urlopen(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("MFA verify error: %s"%error) from None
    # print(result)

    headers = {
        "Origin": "https://%s.auth0.com"%TENANT,
        "Authorization": "Bearer %s"%mfa_transaction_token,
        "x-global-tracking-id": mfa_info["globalTrackingId"]
    }
    request = urllib.request.Request(
        "%s/api/transaction-state"%mfa_info["mfaServerUrl"],
        method="POST",
        headers=headers)
    try:
        response = urllib.request.urlopen(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get MFA result error: %s"%error) from None
    mfa_result = json.loads(result)
    if mfa_result["state"] != "accepted":
        raise RuntimeError("MFA verification is not accepted: %s"%result)
    # print(mfa_result)

    return mfa_result

def get_saml_response(opener, mfa_info, mfa_result):
    """
    get url from mfa_info and post with signature => get saml response from html
    """
    post_fields = {
        "rememberBrowser": "false",
        "signature": mfa_result["token"]
    }
    post_params = urllib.parse.urlencode(post_fields).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://%s.auth0.com"%TENANT
    }
    request = urllib.request.Request(
        mfa_info["postActionURL"],
        data=post_params,
        method="POST",
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get SAMLResponse error: %s"%error) from None
    # print(result)

    saml_response = re.search("<input.+?name=\"SAMLResponse\".+?value=\"(.+?)\"", result).group(1)
    return saml_response

def main():
    # cookie recoding is required otherwise you will see this error:
    # {"statusCode":403,"description":"Invalid state","name":"AnomalyDetected","code":"access_denied"}
    cookie_processor = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_processor)

    login_info = get_login_info(opener)
    connection_name = get_connection_name()
    mfa_info = do_login(opener, login_info, connection_name, USERNAME, PASSWORD)
    mfa_result = do_mfa_verify(mfa_info)
    saml_response = get_saml_response(opener, mfa_info, mfa_result)

    print("Login successful, SAMLResponse:")
    print(saml_response)

if __name__ == "__main__":
    main()
