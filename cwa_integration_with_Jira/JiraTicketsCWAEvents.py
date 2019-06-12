#!/usr/bin/env python
#
# Copyright 2019 Symantec Corporation. All rights reserved.
#
import sys
if sys.version_info[0] < 3 or sys.version_info[1] < 7:
    print("You must have python 3.7 or above to execute the script. Current version is "+str(sys.version_info[0]) +"."+str(sys.version_info[1]))
    exit()
import json
from pathlib import Path
from jira import JIRA
import sys
import requests
import configparser
import os
from datetime import datetime, timedelta
import time
import base64
import logging.config
import re

clientId = None
clientSecret = None
accessToken = None
customerId = None
domainId = None
eventTypeFilterConfig = None
check_severity = None
check_result = None
jiraURL = None
jiraUserName = None
jiraUserPassword = None
jiraProjectId = None
jira = None
jiraAssignee = None
startDate = None
dict_cwa_events = {}
dict_cwa_event_priority = {}
dict_policy_name = {}
dict_check_name = {}
# create logger
logger = logging.getLogger("JiraTicketsCWAEvents")
logger.setLevel(logging.INFO)

# create file handler (fh) and set level to debug
fh = logging.FileHandler('JiraTicketsCWAEvents.log')

# create formatter
formatter = logging.Formatter("%(asctime)s: %(levelname)s: %(message)s",
                              "%Y-%m-%d %H:%M:%S")
# add formatter to console handler
fh.setFormatter(formatter)

# add console handler to logger
logger.addHandler(fh)

configFileName = 'JiraTicketsCWAEventsConfig.ini'
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
LOG_FILE = Path(os.getcwd() + '/create_jira_ticket.log')

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

# Reading values for Jira configuration
logger.info("Reading placeholders of Jira account from " + configFileName + " file.")
JIRA_CONFIG_SECTION = 'JiraConfiguration'
JIRA_URL = 'JiraUrl'
JIRA_PROJECT_ID = 'JiraProjectId'
JIRA_USER_NAME = 'JiraUserName'
JIRA_USER_PASSWORD = 'JiraUserPassword'
JIRA_TICKET_PRIORITY = {'Major': "P2", 'Minor': "P3"}
JIRA_ASSIGN_TO_USER = 'JiraAssigneeUser'

scwaAuthUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/oauth/tokens'
getScwaEventsUrl = 'https://scwp.securitycloud.symantec.com/dcs-service/dcscloud/v1/event/query'

authHeaders = {'Content-type': 'application/json'}
authRequest = {}
eventDatetime = ''

getScwaEventsRequest = {'pageSize': PAGE_SIZE, 'order': 'ASCENDING', 'searchFilter': {}, 'displayLabels': 'false'}


def replace(string, substitutions):
    substrings = sorted(substitutions, key=len, reverse=True)
    regex = re.compile('|'.join(map(re.escape, substrings)))
    return regex.sub(lambda match: substitutions[match.group(0)], string)


def read_values_from_config():
    values_in_config_file = False
    global clientId, clientSecret, eventTypeFilterConfig, check_severity, check_result, jiraURL, jiraUserName, \
        jiraUserPassword, jiraProjectId, jira, jiraAssignee

    try:
        logger.info("Reading values from " + configFileName + " file")
        config = configparser.ConfigParser()
        config.read(CONFIG_INI)

        clientId = config.get(CONFIG_CREDS_SECTION, CLIENT_ID)
        clientSecret = config.get(CONFIG_CREDS_SECTION, CLIENT_SECRET)
        eventTypeFilterConfig = config.get(CONFIG_EVENTS_SECTION, EVENTS_TYPE)
        check_severity = config.get(CONFIG_EVENTS_SECTION, CHECK_SEVERITY)
        jiraURL = config.get(JIRA_CONFIG_SECTION, JIRA_URL)
        jiraUserName = config.get(JIRA_CONFIG_SECTION, JIRA_USER_NAME)
        jiraUserPassword = config.get(JIRA_CONFIG_SECTION, JIRA_USER_PASSWORD)
        jiraProjectId = config.get(JIRA_CONFIG_SECTION, JIRA_PROJECT_ID)
        jiraAssignee = config.get(JIRA_CONFIG_SECTION, JIRA_ASSIGN_TO_USER)

        if clientId == "" or clientSecret == "" or eventTypeFilterConfig == "" or check_severity == "" \
                or jiraURL == "" or jiraUserName == "" or jiraUserPassword == "" or jiraProjectId == "" \
                or jiraAssignee == "":
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


def authenticate_jira():
    is_jira_authenticate = False
    try:
        logger.info("Authenticating user credentials to access Jira")
        authenticate_jira.jiraUserPassword = base64.b64decode(jiraUserPassword).decode('utf-8')
        global jira
        jira = JIRA(server=jiraURL, basic_auth=(jiraUserName, authenticate_jira.jiraUserPassword))
        is_jira_authenticate = True
    except Exception as ex:
        logger.error("Exception occurred while authenticating Jira " + str(ex))
    return is_jira_authenticate


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
        eventTypeFilter = '( type_class = ' + eventTypesWithQuotes + ') && (check_severity=\"' + check_severity + '\" )'
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
                if scwaEvent['check_result'] == "Fail":
                    if not scwaEvent['resource_name']:
                        resource_name="NA"
                    else:
                        resource_name=scwaEvent['resource_name']
                    dict_cwa_events.setdefault(eventSummary, {})[scwaEvent['resource_id']] = \
                        "|" + resource_name.replace("|","\\|") + "|" + scwaEvent['resource_id'].replace("|","\\|") + \
                        "|" + scwaEvent['check_evidence'].replace("|","\\|") + "|"
                    dict_cwa_event_priority.setdefault(eventSummary, JIRA_TICKET_PRIORITY[scwaEvent["severity_id_d"]])
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


def create_tickets_in_Jira():
    create_tickets_in_Jira.not_processed_resources = []
    create_tickets_in_Jira.tickets_updated = []
    create_tickets_in_Jira.tickets_created = []
    try:
        if dict_cwa_events:
            for event in list(dict_cwa_events):
                all_impacted_resources = ""
                if len(dict_cwa_events[event].items()) < 1:
                    del dict_cwa_events[event]
                    continue
                logger.info("Creating jira tickets for events")
                for key, value in dict_cwa_events[event].items():
                    all_impacted_resources = all_impacted_resources + value + ' \n '
                try:
                    jira_ticket_summary = replace(event, {"-": "\\\\-", "\'": "\\\\\'"})
                    jira_ticket = jira.search_issues(jql_str="summary ~ \"" + jira_ticket_summary + "\" "
                                                                                                    "AND status not in  (Closed,Done,Resolved)")
                    if jira_ticket:
                        logger.info(
                            "Jira ticket " + str(jira_ticket[0].key) + " is already exist for \"" + str(
                                jira_ticket[0].fields.summary) +
                            "\" \n  Same will be updated with details of new resource ")
                        existing_description = jira_ticket[0].fields.description
                        if not existing_description:
                            existing_description = ""
                        jira_ticket[0].update(fields={'description': existing_description + all_impacted_resources})
                        logger.info("Jira ticket " + str(jira_ticket[0].key) +
                                    " updated with new misconfigured resources. ")
                        create_tickets_in_Jira.tickets_updated.append("\n" + str(jira_ticket[0].key) + " " +
                                                                      str(jira_ticket[0].fields.summary))
                        jira.assign_issue(jira_ticket[0], jiraAssignee)

                    else:
                        priority = dict_cwa_event_priority[event]
                        header = "|*+Resource Name+*|*+Resource id+*|*+Evidence+*| \n"
                        new_description = "*+Policy Name+* :- " + dict_policy_name[event] + '\n' + \
                                          "*+Check Name+* :- " + dict_check_name[event] + '\n' + \
                                          "*+Impacted Resources+* :- \n " + \
                                          header + all_impacted_resources

                        new_jira_ticket_details = {'project': {'id': jiraProjectId}, 'summary': event,
                                                   'description': new_description,
                                                   'issuetype': {'name': 'Defect'},
                                                   'priority': {'name': priority},
                                                   }
                        new_ticket = jira.create_issue(new_jira_ticket_details)
                        create_tickets_in_Jira.tickets_created.append("\n" + str(new_ticket.key) + " " +
                                                                      str(new_ticket.fields.summary))
                        logger.info("A jira ticket " + str(new_ticket.key) + " has been created with details " +
                                    str(new_ticket.fields.summary))
                        jira.assign_issue(new_ticket, jiraAssignee)

                except Exception as ex:
                    logger.error("Exception occurred while creating Jira ticket " + str(ex))
                    if "project is required" in str(ex):
                        logger.error("Cannot proceed, Jira project id is not correct no new tickets will be created. ")
                        create_tickets_in_Jira.not_processed_resources.append("Policy Name "+dict_policy_name[event]+ " Check Name " +dict_check_name[event]+ "\n"+ all_impacted_resources)
                    elif "User '" + jiraAssignee + "' does not exist" in str(ex):
                        logger.error("Could not assign , Jira ticket to  user "+jiraAssignee+", user  does not exist")
                    else:
                        create_tickets_in_Jira.not_processed_resources.append(all_impacted_resources)
                    continue

    except Exception as ex:
        logger.error("Exception occurred while creating ticket in Jira " + str(ex))
        report_not_processed_resources()


def report_not_processed_resources():
    try:
        events_collected = len(dict_cwa_events)
        tickets_created = len(create_tickets_in_Jira.tickets_created)
        tickets_updated = len(create_tickets_in_Jira.tickets_updated)
        if events_collected > 0:
            formatter = logging.Formatter("%(message)s")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            if tickets_created > 0:
                logger.info("===============================================")
                logger.info("Following are the newly created Jira tickets:- ")
                logger.info("===============================================")
                bullet = 0
                for new_ticket in create_tickets_in_Jira.tickets_created:
                    bullet += 1
                    logger.info(str(bullet) + "." + new_ticket)
            else:
                logger.info("No new ticket was created.")
            if tickets_updated > 0:
                logger.info("======================================================================================")
                logger.info("Following tickets were already created and updated with new misconfigured resources:- ")
                logger.info("======================================================================================")
                bullet = 0
                for updated_ticket in create_tickets_in_Jira.tickets_updated:
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
                logger.error("Could not open a Jira ticket for following Policies and Checks :- \n")
                for resource in create_tickets_in_Jira.not_processed_resources:
                    logger.error(resource)
        else:
            logger.info("All misconfigured resources seem to be fixed now. ")
    except Exception as ex:
        logger.error("Exception occurred while summarizing result of the run. " + str(ex))


if read_values_from_config():
    if authenticate_cwa_customer():
        if authenticate_jira():
            if get_cwa_events():
                create_tickets_in_Jira()
                report_not_processed_resources()
