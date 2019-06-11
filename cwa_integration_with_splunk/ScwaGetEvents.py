#!/usr/bin/env python
#
# Copyright 2017 Symantec Corporation. All rights reserved.
#
import json
import requests
import configparser
import os
from datetime import datetime, timedelta
import time
import sys
import splunklib.client as client
import logging.config

CUSTOMER_ID = 'CUSTOMER_ID'
DOMAIN_ID = 'DOMAIN_ID'
CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'CLIENT_SECRET'

if os.name == 'nt':
    SPLUNK_HOME = 'C:\Program Files\Splunk'
else:
    SPLUNK_HOME = '/opt/splunk'

PAGE_SIZE = 100
RETRY_COUNT = 3
CONFIG_INI = os.path.join(SPLUNK_HOME, 'bin', 'scripts', 'ScwaGetEventsConfig.ini')
STATUS_INI = os.path.join(SPLUNK_HOME, 'bin', 'scripts', 'ScwaGetEventsStatus.status')
STATUS_DATES_SECTION = 'ScwaGetEventsDates'
CONFIG_CREDS_SECTION = 'Credentials'
CONFIG_EVENTS_SECTION = 'Events'
START_DATE = 'startDate'
EVENT_TYPE_FILTER = 'EventTypeFilter'
GET_EVENTS_FROM_DAYS = 'GetEventsFromDays'
USE_CREDS_FROM_SPLUNK_STORAGE = 'UseCredsFromSplunkStorage'
SCWP_API_KEYS_REALM = "ScwaApiKeyCreds"

scwaAuthUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'
getScwaEventsUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/event/query'

authHeaders = {'Content-type': 'application/json'}
authRequest = {}
eventDatetime = ''

getScwaEventsRequest = {'pageSize': PAGE_SIZE, 'order': 'ASCENDING', 'searchFilter': {}, 'displayLabels': 'false'}


def setupLogging(
        default_path='logging.json',
        default_level=logging.INFO,
        env_key='LOG_CFG'
):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


def updateStatusIniFile():
    config = configparser.RawConfigParser()
    config.add_section(STATUS_DATES_SECTION)
    config.set(STATUS_DATES_SECTION, START_DATE, eventDatetime)
    with open(STATUS_INI, 'w') as configfile:
        config.write(configfile)


def getCreds():
    Config = configparser.ConfigParser()
    Config.read(CONFIG_INI)
    useCredsFromSplunkStorage = Config.get(CONFIG_CREDS_SECTION, USE_CREDS_FROM_SPLUNK_STORAGE)
    if useCredsFromSplunkStorage == 'true':
        return getCredsFromSplunkStorage()
    return {'clientId': Config.get(CONFIG_CREDS_SECTION, CLIENT_ID),
            'clientSecretKey': Config.get(CONFIG_CREDS_SECTION, CLIENT_SECRET)}


def getCredsFromSplunkStorage():
    for line in sys.stdin:
        session_key = line
    splunkService = client.connect(token=session_key)
    storage_passwords = splunkService.storage_passwords
    current_credentials = [k for k in storage_passwords if k.content.get('realm') == SCWP_API_KEYS_REALM]
    if len(current_credentials) == 0:
        raise Exception("No SCWP credentials found in Splunk storage.")
    else:
        for current_credential in current_credentials:
            scwaCreds = {'clientId': current_credential.content.get('username'),
                         'clientSecretKey': current_credential.content.get('clear_password')}
            return scwaCreds


def authenticate():
    for retry in range(RETRY_COUNT):
        authRequestJson = json.dumps(authRequest)
        authResponse = requests.post(scwaAuthUrl, data=authRequestJson, headers=authHeaders, verify=False)
        if authResponse.status_code != requests.codes.ok:
            if retry >= RETRY_COUNT:
                authResponse.raise_for_status()
            time.sleep(retry * 60)
            continue
        else:
            break
    accessToken = authResponse.json()['access_token']
    authHeaders['Authorization'] = 'Bearer ' + accessToken


try:
    # setupLogging()
    Config = configparser.ConfigParser()
    Config.read(CONFIG_INI)
    customerId = Config.get(CONFIG_CREDS_SECTION, CUSTOMER_ID)
    domainId = Config.get(CONFIG_CREDS_SECTION, DOMAIN_ID)
    creds = getCreds()
    clientId = creds.get('clientId')
    clientSecret = creds.get('clientSecretKey')
    eventTypeFilterConfig = Config.get(CONFIG_EVENTS_SECTION, EVENT_TYPE_FILTER)

    authHeaders['x-epmp-customer-id'] = customerId
    authHeaders['x-epmp-domain-id'] = domainId
    authRequest['client_id'] = clientId
    authRequest['client_secret'] = clientSecret

    statusIni = configparser.ConfigParser()
    statusIni.read(STATUS_INI)
    startDate = statusIni.get(STATUS_DATES_SECTION, START_DATE)
    getEventsFromDays = Config.getint(CONFIG_EVENTS_SECTION, GET_EVENTS_FROM_DAYS)
    if (startDate is None) or (startDate == ""):
        startDate = (datetime.today() - timedelta(days=getEventsFromDays)).isoformat()
    else:
        if startDate.endswith('Z'):
            startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(milliseconds=1)).isoformat()
        else:
            startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(milliseconds=1)).isoformat()

    eventTypes = eventTypeFilterConfig.strip().split(',')
    eventTypesWithQuotes = ','.join('\"{0}\"'.format(eventType) for eventType in eventTypes)
    eventTypeFilter = 'type_class IN [' + eventTypesWithQuotes + ']'

    getScwaEventsRequest['startDate'] = startDate
    getScwaEventsRequest['endDate'] = datetime.now().isoformat()
    getScwaEventsRequest['additionalFilters'] = eventTypeFilter
    eventDatetime = startDate

    pageNumber = 0
    while True:
        getScwaEventsRequest['pageNumber'] = pageNumber
        getScwaEventsRequestJson = json.dumps(getScwaEventsRequest)
        scwaEventsResponse = requests.post(getScwaEventsUrl, data=getScwaEventsRequestJson, headers=authHeaders, verify=False)

        if scwaEventsResponse.status_code == 401:
            authenticate()
            scwaEventsResponse = requests.post(getScwaEventsUrl, data=getScwaEventsRequestJson, headers=authHeaders, verify=False)

        if scwaEventsResponse.status_code != requests.codes.ok:
            scwaEventsResponse.raise_for_status()

        scwaEventsJson = scwaEventsResponse.json()
        scwaEvents = scwaEventsJson['result']
        totalScwaEvents = scwaEventsJson['total']

        if totalScwaEvents == 0:
            break

        for scwaEvent in scwaEvents:
            print(json.dumps(scwaEvent))
            print('\n')
            sys.stdout.flush()
            eventDatetime = scwaEvent['time']

        pageNumber += 1
except:
    raise
finally:
    updateStatusIniFile()
