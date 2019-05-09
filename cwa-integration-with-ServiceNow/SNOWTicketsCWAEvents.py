
#!/usr/bin/env python
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
import json
from pathlib import Path
import sys
import requests
import configparser
import os
from datetime import datetime, timedelta
import time
import base64
import logging.config
import re
import pysnow
clientId = None
clientSecret = None
accessToken = None
customerId = None
domainId = None
eventTypeFilterConfig = None
snowInstance = None
snowUserName = None
snowUserPassword = None
snow_incident = None
snow_summary_max_char = None
startDate = None
eventSummary = None
dict_cwa_events = {}
dict_cwa_event_priority = {}
dict_policy_name = {}
dict_check_name = {}
# create logger
logger = logging.getLogger("SNOWTicketsCWAEvents")
logger.setLevel(logging.INFO)

# create file handler (fh) and set level to debug
fh = logging.FileHandler('SNOWTicketsCWAEvents.log')

# create formatter
formatter = logging.Formatter("%(asctime)s: %(levelname)s: %(message)s",
                              "%Y-%m-%d %H:%M:%S")
# add formatter to console handler
fh.setFormatter(formatter)

# add console handler to logger
logger.addHandler(fh)

configFileName = 'SNOWTicketsCWAEventsConfig.ini'
# Setting variables from config.ini file
# Reading customer account information
logger.info("Reading place holders for CWA customer account information from " + configFileName + " file")
CUSTOMER_ID = 'CUSTOMER_ID'
DOMAIN_ID = 'DOMAIN_ID'
CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'CLIENT_SECRET'

# Reading and creating paths of required files
logger.info("Reading and creating path for required files.")
CONFIG_INI = Path(os.getcwd() + '/' + configFileName)
LOG_FILE = Path(os.getcwd() + '/create_SNOW_ticket.log')

if not CONFIG_INI.is_file():
    logger.error(
        " File " + str(CONFIG_INI) + " is missing. " "Place the missing  file in directory " + str(
            Path(os.getcwd())) + " and re-run the script.")
    exit()
# Reading values for parameters to be used in getEvent API
logger.info("Reading placeholders for parameters to be used in getEvent API request body.")
STATUS_DATES_SECTION = 'ScwaGetEventsDates'
CONFIG_CREDS_SECTION = 'Credentials'
CONFIG_EVENTS_SECTION = 'Events'
START_DATE = 'startDate'
EVENTS_TYPE = 'EventsType'
CHECK_SEVERITY = 'CheckSeverity'
CEHCK_EVALUATION_STATUS = 'CheckEvalResult'
GET_EVENTS_FROM_DAYS = 'GetEventsFromDays'
PAGE_SIZE = 100
RETRY_COUNT = 3

# Reading values for SNOW configuration
logger.info("Reading placeholders of SNOW account from " + configFileName + " file.")
SNOW_CONFIG_SECTION = 'SNOWConfigurations'
SNOW_INSTANCE = 'SnowInstance'
SNOW_USER_NAME = 'SnowUserName'
SNOW_USER_PASSWORD = 'SnowPassword'
SNOW_TICKET_PRIORITY = {'Major': "2", 'Minor': "3", 'Warning' : "4"}
SNOW_SUMMARY_MAX_CHAR_LIMIT = 'SnowSummaryFiledLimit'
scwaAuthUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'
getScwaEventsUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/event/query'
authHeaders = {'Content-type': 'application/json'}
authRequest = {}
eventDatetime = ''
html_prefix="<style>table {border-collapse: collapse;}th, td {border: 1px solid black;padding: 10px;text-align: left;}</style><table><tr>"
html_postfix="</th></tr></table>"
getScwaEventsRequest = {'pageSize': PAGE_SIZE, 'order': 'ASCENDING', 'searchFilter': {}, 'displayLabels': 'false'}


def replace(string, substitutions):
    substrings = sorted(substitutions, key=len, reverse=True)
    regex = re.compile('|'.join(map(re.escape, substrings)))
    return regex.sub(lambda match: substitutions[match.group(0)], string)


def read_values_from_config():
    values_in_config_file = False
    global clientId, clientSecret,snowInstance, snowUserName, snowUserPassword, eventTypeFilterConfig,  \
          check_severity,snow_summary_max_char

    try:
        logger.info("Reading values from " + configFileName + " file")
        config = configparser.ConfigParser()
        config.read(CONFIG_INI)

        clientId = config.get(CONFIG_CREDS_SECTION, CLIENT_ID)
        clientSecret = config.get(CONFIG_CREDS_SECTION, CLIENT_SECRET)
        snowInstance = config.get(SNOW_CONFIG_SECTION, SNOW_INSTANCE)
        snowUserName = config.get(SNOW_CONFIG_SECTION, SNOW_USER_NAME)
        snowUserPassword = config.get(SNOW_CONFIG_SECTION, SNOW_USER_PASSWORD)
        snow_summary_max_char = config.get(SNOW_CONFIG_SECTION, SNOW_SUMMARY_MAX_CHAR_LIMIT)
        eventTypeFilterConfig = config.get(CONFIG_EVENTS_SECTION, EVENTS_TYPE)
        check_severity = config.get(CONFIG_EVENTS_SECTION, CHECK_SEVERITY)

        if clientId == "" or clientSecret == "" or eventTypeFilterConfig == "" or snowInstance == "" \
                or snowUserName == "" or snowUserPassword == "" \
                 or check_severity == "" or snow_summary_max_char == "":
            logger.error("One or more required values are missing in " + configFileName + " file ")
            exit()
        else:
            values_in_config_file = True
    except Exception as ex:
        logger.error("Exception occurred while reading values from " + configFileName + " file " + str(ex))

    return values_in_config_file


def authenticate_cwa_customer():
    is_authenticate = False
    try:
        logger.info("Authenticating CWA customer and fetching authorization token, customer ID and domain ID ")
        authRequest['client_id'] = clientId
        authRequest['client_secret'] = clientSecret
        for retry in range(RETRY_COUNT):
            authRequestJson = json.dumps(authRequest)
            authResponse = requests.post(scwaAuthUrl, data=authRequestJson, headers=authHeaders)
            if authResponse.status_code != requests.codes.ok:
                if retry >= RETRY_COUNT:
                    authResponse.raise_for_status()
                time.sleep(retry * 60)
                continue
            else:
                break
        accessToken = authResponse.json()['access_token']
        customerId = authResponse.json()['x-epmp-customer-id']
        domainId = authResponse.json()['x-epmp-domain-id']
        authHeaders['Authorization'] = 'Bearer ' + accessToken
        authHeaders['x-epmp-customer-id'] = customerId
        authHeaders['x-epmp-domain-id'] = domainId
        logger.info("Authentication successful")
        is_authenticate = True
    except Exception as ex:
        logger.error("Exception occurred while authenticating customer with CWA" + str(ex))
    return is_authenticate


def authenticate_snow():
    is_snow_authenticate = False
    try:
        logger.info("Authenticating user credentials to access ServiceNow")
        authenticate_snow.snowUserPassword = base64.b64decode(snowUserPassword).decode('utf-8')
        global snow_incident
        snow_connection = pysnow.Client(instance=snowInstance, user=snowUserName, password=authenticate_snow.snowUserPassword)
        # Define a resource, here we'll use the incident table API
        snow_incident = snow_connection.resource(api_path='/table/incident')
        is_snow_authenticate = True
    except Exception as ex:
        logger.error("Exception occurred while authenticating ServiceNow " + str(ex))
    return is_snow_authenticate


def get_cwa_events():
    events_gathered_successfully = False
    global startDate
    try:
        logger.info("Preparing request payload for get cwa events.")
        config = configparser.ConfigParser()
        config.read(CONFIG_INI)
        getEventsFromDays = config.getint(CONFIG_EVENTS_SECTION, GET_EVENTS_FROM_DAYS)
        if getEventsFromDays <= 0:
            logger.error("GetEventsFromDays cannot be negative number or a zero . Provide a positive number grater than zero.")
            exit ()
        if (startDate is None) or (startDate == ""):
            startDate = (datetime.today() - timedelta(days=getEventsFromDays)).isoformat()
        else:
            if startDate.endswith('Z'):
                startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(
                    milliseconds=1)).isoformat()
            else:
                startDate = (datetime.strptime(startDate, '%Y-%m-%dT%H:%M:%S.%f') + timedelta(
                    milliseconds=1)).isoformat()

        eventTypes = eventTypeFilterConfig.strip().split(',')
        eventTypesWithQuotes = ','.join('\"{0}\"'.format(eventType) for eventType in eventTypes)
        check_severities = check_severity.strip().split(',')
        severity='||'.join(["(check_severity=\"" + severity + "\" )" for severity in check_severities])
        eventTypeFilter = '( type_class = ' + eventTypesWithQuotes + ') && ('+severity+') '
        getScwaEventsRequest['startDate'] = startDate
        getScwaEventsRequest['endDate'] = datetime.now().isoformat()
        getScwaEventsRequest['additionalFilters'] = eventTypeFilter
        pageNumber = 0
        global dict_cwa_events
        while True:
            getScwaEventsRequest['pageNumber'] = pageNumber
            getScwaEventsRequestJson = json.dumps(getScwaEventsRequest)
            scwaEventsResponse = requests.post(getScwaEventsUrl, data=getScwaEventsRequestJson, headers=authHeaders)
            scwaEventsJson = scwaEventsResponse.json()
            scwaEvents = scwaEventsJson['result']
            totalScwaEvents = scwaEventsJson['total']

            if totalScwaEvents == 0:
                if pageNumber == 0:
                    logger.info("No new events were found between "+startDate + " and "+  getScwaEventsRequest['endDate'])
                    exit()
                break

            for scwaEvent in scwaEvents:
                eventSummary = "Misconfiguration has been reported on \'" + \
                               scwaEvent['service_name'] + "\' by check \'" + scwaEvent['check_name'] + "\' on \'" + \
                               scwaEvent['account_name'] + "\'"
                if len(eventSummary) > int(snow_summary_max_char):
                    eventSummary = "Misconfiguration has been reported on \'" + \
                               scwaEvent['service_name'] + "\' by check \'" + scwaEvent['check_id'] + "\' on \'" + \
                               scwaEvent['account_name'] + "\'"
                if scwaEvent['check_result'] == "Fail":
                    if not scwaEvent['resource_name']:
                        resource_name="NA"
                    else:
                        resource_name=scwaEvent['resource_name']
                    dict_cwa_events.setdefault(eventSummary, {})[scwaEvent['resource_id']] = html_prefix+"<th><u> Resource Name :- </u>" +resource_name + "</th>"+\
                                                                                             "<th><u> Resource ID :- </u>" +scwaEvent['resource_id']+ "</th>"+\
                                                                                             "<th><u>  Check Evidence :- </u>" +scwaEvent['check_evidence'] +"</th>"+html_postfix
                    dict_cwa_event_priority.setdefault(eventSummary, SNOW_TICKET_PRIORITY[scwaEvent["severity_id_d"]])
                    dict_policy_name.setdefault(eventSummary, scwaEvent['policy_name'])
                    dict_check_name.setdefault(eventSummary, scwaEvent['check_name'])
                else:
                    if dict_cwa_events:
                        for record in dict_cwa_events:
                            for key, value in list(dict_cwa_events[record].items()):
                                if key == scwaEvent['resource_id']:
                                    del dict_cwa_events[record][key]
                sys.stdout.flush()

            pageNumber += 1
        events_gathered_successfully = True
    except Exception as ex:
        logger.error("Cannot proceed further. Exception occurred while fetching cwa events " + str(ex) + " .")
    return events_gathered_successfully

def snow_incident_already_exists(search_result_response):
    response_json = json.loads(search_result_response._response.text)
    incident_id = None
    if len(response_json['result']) < 1:
        return incident_id
    index=0
    while (index< len(response_json['result'])):
        incident_state=response_json['result'][index]['incident_state']
        if incident_state == "6" or incident_state == "7" or incident_state == "8":
            incident_id = None
        else:
            incident_id = response_json['result'][index]['number']
            break
        index = index+1
    return  incident_id

def snow_get_incident_details(update_incident_response):
    incident_details = {}
    update_incident_responsejson = json.loads(update_incident_response._response.text)
    incident_details["number"]=str(update_incident_responsejson['result']['number'])
    incident_details['short_description']=update_incident_responsejson['result']['short_description']
    return incident_details

def create_tickets_in_SNOW():
    create_tickets_in_SNOW.not_processed_resources = []
    create_tickets_in_SNOW.tickets_updated = []
    create_tickets_in_SNOW.tickets_created = []
    try:
        if dict_cwa_events:
            for event in list(dict_cwa_events):
                all_impacted_resources = ""
                if len(dict_cwa_events[event].items()) < 1:
                    del dict_cwa_events[event]
                    continue
                logger.info("Creating tickets in ServiceNow for CWA events")
                for key, value in dict_cwa_events[event].items():
                    all_impacted_resources = all_impacted_resources + value + ' \n '
                try:
                    #snow_ticket_summary = replace(event, {"-": "\\\\-", "\'": "\\\\\'"})
                    snow_ticket_search = snow_incident.get(query={'short_description': event})
                    snow_ticket=snow_incident_already_exists(snow_ticket_search)
                    if snow_ticket != None:
                        new_comment = "[code]<h3><u>Policy Name</u></h3>" + dict_policy_name[event] + '\n' + \
                                          "[code]<h3><u>Check Name</u></h3>" + dict_check_name[event] + '\n' + \
                                          "[code]<h3><u>Impacted Resources</u></h3>\n " + "[code]"+all_impacted_resources
                        updated_incident = snow_incident.update(query={'number': snow_ticket},
                                                         payload={'comments':new_comment})
                        incident_details=snow_get_incident_details(updated_incident)
                        logger.info("ServiceNow ticket " + str(incident_details['number']) +
                                    " updated with new misconfigured resources. ")
                        create_tickets_in_SNOW.tickets_updated.append("\n" + str(incident_details['number']) + " " +
                                                                      str(incident_details['short_description']))

                    else:
                        priority = dict_cwa_event_priority[event]
                        new_description = "[code]<h3><u>Policy Name</u></h3>" + dict_policy_name[event] + '\n' + \
                                          "[code]<h3><u>Check Name</u></h3>" + dict_check_name[event] + '\n' + \
                                          "[code]<h3><u>Impacted Resources</u></h3>\n " + "[code]"+all_impacted_resources

                        new_snow_ticket_details = {'short_description': event,
                                                   'comments': new_description,
                                                   'urgency': priority,
                                                   'priority':  priority,
                                                   'incident_state': 1
                                                   }
                        new_ticket = snow_incident.create(payload=new_snow_ticket_details)
                        incident_details = snow_get_incident_details(new_ticket)
                        create_tickets_in_SNOW.tickets_created.append("\n" + str(incident_details['number']) + " " +
                                                                      str(incident_details['short_description']))
                        logger.info("ServiceNow ticket " + str(incident_details['number']) + " has been created with details " +
                                    str(incident_details['short_description']))

                except Exception as ex:
                    logger.error("Exception occurred while creating ServiceNow ticket " + str(ex))
                    create_tickets_in_SNOW.not_processed_resources.append(all_impacted_resources)
                    continue

    except Exception as ex:
        logger.error("Exception occurred while creating ticket in ServiceNow " + str(ex))


def report_not_processed_resources():
    try:
        events_collected = len(dict_cwa_events)
        tickets_created = len(create_tickets_in_SNOW.tickets_created)
        tickets_updated = len(create_tickets_in_SNOW.tickets_updated)
        if events_collected > 0:
            formatter = logging.Formatter("%(message)s")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            if tickets_created > 0:
                logger.info("======================================================")
                logger.info("Following are the newly created ServiceNow tickets:- ")
                logger.info("======================================================")
                bullet = 0
                for new_ticket in create_tickets_in_SNOW.tickets_created:
                    bullet += 1
                    logger.info(str(bullet) + "." + new_ticket)
            else:
                logger.info("No new ticket was created.")
            if tickets_updated > 0:
                logger.info("======================================================================================")
                logger.info("Following tickets were already created and updated with new misconfigured resources:- ")
                logger.info("======================================================================================")
                bullet = 0
                for updated_ticket in create_tickets_in_SNOW.tickets_updated:
                    bullet += 1
                    logger.info(str(bullet) + "." + updated_ticket)
            else:
                logger.info("All tickets were newly created.")
            if tickets_updated > 0 or tickets_created > 0:
                logger.info("=============================================\n"
                            "SUMMARY")
                logger.info("New tickets created:- " + str(tickets_created))
                logger.info("Existing tickets updated:- " + str(tickets_updated))
                logger.info("=============================================\n")
            if events_collected != (tickets_created + tickets_updated):
                logger.error("Could not open a ServiceNow ticket for following Policies and Checks :- \n")
                for resource in create_tickets_in_SNOW.not_processed_resources:
                    logger.error(resource)
        else:
            logger.info("All misconfigured resources seem to be fixed now. ")
    except Exception as ex:
        logger.error("Exception occurred while summarizing result of the run. " + str(ex))


if read_values_from_config():
    if authenticate_cwa_customer():
        if authenticate_snow():
            if get_cwa_events():
                create_tickets_in_SNOW()
                report_not_processed_resources()
