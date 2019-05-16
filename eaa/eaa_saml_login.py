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
import os
import hashlib

# Parameters
URL="" # idp URL
USERNAME=""
PASSWORD=""
NAVIGATOR_ID=hashlib.sha256(os.urandom(256)).hexdigest() # browser fingerprint
LANGUAGE="english"

def get_login_info(opener):
    """
    access url => get parameters from hidden fields in html
    """
    request = urllib.request.Request(URL)
    response = opener.open(request)
    html = response.read().decode()
    # print(html)

    login_info = {
        "xsrf": re.search("<input.+?id=\"xsrf\".+?value=\"(.+?)\"", html).group(1),
        "xctx": re.search("<input.+?id=\"xctx\".+?value=\"(.+?)\"", html).group(1),
        "xversion": re.search("<input.+?id=\"xversion\".+?value=\"(.+?)\"", html).group(1),
    }
    # print(login_info)

    return login_info

def do_login(opener, login_info, username, password):
    """
    post json to /api/v1/login => get login result in json
    """
    login_payload = {
        "navigator": "{}",
        "password": password,
        "username": username,
    }
    login_payload_json = json.dumps(login_payload).encode()
    # print(login_payload)

    headers = {
        "Content-Type": "application/json",
        "Origin": URL,
        "x-language": LANGUAGE,
        "x-navigator-id": NAVIGATOR_ID,
        "xctx": login_info["xctx"],
        "xsrf": login_info["xsrf"]
    }
    request = urllib.request.Request(
        "%s/api/v1/login"%URL,
        data=login_payload_json,
        method="POST",
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Login error: %s"%error) from None
    login_result = json.loads(result)
    # print(login_result)

    return login_result

def get_app_info(opener, login_info):
    """
    get app list from /api/v1/apps => choose app
    """
    headers = {
        "Origin": URL,
        "x-language": LANGUAGE,
        "x-navigator-id": NAVIGATOR_ID,
        "xctx": login_info["xctx"],
        "xsrf": login_info["xsrf"]
    }
    request = urllib.request.Request(
        "%s/api/v1/apps"%URL,
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get apps error: %s"%error) from None
    apps_info = json.loads(result)
    # print(apps_info)

    apps = apps_info["apps"]
    if len(apps) == 0:
        raise RuntimeError("No app available")
    elif len(apps) == 1:
        app_info = apps[0]
    else:
        print("Please enter the index of app that contains your account:")
        for index, app in enumerate(apps):
            print("%d: %s"%(index+1, app["name"]))
        index = int(input("index: "))-1
        app_info = apps[index]
    print("Use app: %s"%(app_info["name"]))
    return app_info

def get_mfa_info(opener, login_info, app_info):
    """
    call /api/v2/apps/navigate => get nativate url from json =>
    get mfa info from html =>
    call /api/v1/mfa/token/settings => get verify method and target from json
    """
    navigate_payload = {
        "hostname": app_info["hostname"]
    }
    navigate_payload_json = json.dumps(navigate_payload).encode()
    # print(navigate_payload)

    headers = {
        "Content-Type": "application/json",
        "Origin": URL,
        "x-language": LANGUAGE,
        "x-navigator-id": NAVIGATOR_ID,
        "xctx": login_info["xctx"],
        "xsrf": login_info["xsrf"]
    }
    request = urllib.request.Request(
        "%s/api/v2/apps/navigate"%URL,
        data=navigate_payload_json,
        method="POST",
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get navigate url error: %s"%error) from None
    navigate_result = json.loads(result)
    navigate_url = navigate_result["navigate"]["url"]
    # print(navigate_result)

    request = urllib.request.Request("%s%s"%(URL, navigate_url))
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get MFA info error: %s"%error) from None
    mfa_info = {
        "xsrf": re.search("<input.+?id=\"xsrf\".+?value=\"(.+?)\"", result).group(1),
        "xctx": re.search("<input.+?id=\"xctx\".+?value=\"(.+?)\"", result).group(1),
        "xversion": re.search("<input.+?id=\"xversion\".+?value=\"(.+?)\"", result).group(1),
    }
    # print(mfa_info)

    headers = {
        "Origin": URL,
        "x-language": LANGUAGE,
        "x-navigator-id": NAVIGATOR_ID,
        "xctx": mfa_info["xctx"],
        "xsrf": mfa_info["xsrf"]
    }
    request = urllib.request.Request(
        "%s/api/v1/mfa/token/settings"%URL,
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get MFA token settings error: %s"%error) from None
    mfa_settings = json.loads(result)
    # print(mfa_settings)

    mfa_info["option"] = mfa_settings["mfa"]["settings"]["preferred"]["option"]
    mfa_option_value = mfa_settings["mfa"]["settings"][mfa_info["option"]][0]
    mfa_info["uuid"] = mfa_option_value["uuid"]
    mfa_info["target"] = mfa_option_value.get("value", mfa_info["uuid"])
    return mfa_info

def do_mfa_verify(opener, mfa_info):
    """
    call /api/v1/mfa/user/{option}/token/push => sent verify code to target if not totp =>
    ask verification code  =>
    call /api/v1/mfa/user/{option}/token/verify => get json with html body which contains saml response
    """
    push_payload = {
        "force": False,
        "uuid": mfa_info["uuid"]
    }
    push_payload_json = json.dumps(push_payload).encode()
    # print(push_payload)

    headers = {
        "Content-Type": "application/json",
        "Origin": URL,
        "x-language": LANGUAGE,
        "x-navigator-id": NAVIGATOR_ID,
        "xctx": mfa_info["xctx"],
        "xsrf": mfa_info["xsrf"]
    }
    if mfa_info["option"] != "totp":
        request = urllib.request.Request(
            "%s/api/v1/mfa/user/%s/token/push"%(URL, mfa_info["option"]),
            data=push_payload_json,
            method="POST",
            headers=headers)
        try:
            response = opener.open(request)
            result = response.read().decode()
        except urllib.error.HTTPError as e:
            error = e.read().decode()
            raise RuntimeError("Push MFA verification code error: %s"%error) from None
        # print(result)

    mfa_code = input("Please enter your MFA verification code from %s [ %s ]: "%(
        mfa_info["option"], mfa_info["target"]))
    verify_payload = {
        "category": mfa_info["option"],
        "token": mfa_code,
        "uuid": mfa_info["uuid"]
    }
    verify_payload_json = json.dumps(verify_payload).encode()
    # print(verify_payload)

    request = urllib.request.Request(
        "%s/api/v1/mfa/user/%s/token/verify"%(URL, mfa_info["option"]),
        data=verify_payload_json,
        method="POST",
        headers=headers)
    try:
        response = opener.open(request)
        result = response.read().decode()
    except urllib.error.HTTPError as e:
        error = e.read().decode()
        raise RuntimeError("Get navigate url error: %s"%error) from None
    mfa_result = json.loads(result)
    # print(mfa_result)

    return mfa_result

def get_saml_response(mfa_result):
    """
    get saml response from html body in mfa result json
    """
    html = mfa_result["response"]["body"]
    saml_response = re.search("<input.+?name=\"SAMLResponse\".+?value=\"(.+?)\"", html).group(1)
    return saml_response

def main():
    cookie_processor = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_processor)

    login_info = get_login_info(opener)
    login_result = do_login(opener, login_info, USERNAME, PASSWORD)
    app_info = get_app_info(opener, login_info)
    mfa_info = get_mfa_info(opener, login_info, app_info)
    mfa_result = do_mfa_verify(opener, mfa_info)
    saml_response = get_saml_response(mfa_result)

    print("Login successful, SAMLResponse:")
    print(saml_response)

if __name__ == "__main__":
    main()
