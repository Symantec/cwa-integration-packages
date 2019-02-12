1. Login to SCWA Portal → Settings → General Settings → API Keys. Copy CUSTOMER_ID, DOMAIN_ID, CLIENT_ID and CLIENT_SECRET values.
2. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Credentials' section. Update respective keys with the values copied in the above step.
3. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Events' section. Update key 'EventTypeFilter' with following  value: 
Compliance
 	a) e.g. Setting 'EventTypeFilter=Compliance' will get Compliance events into Splunk.
4. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Events' section. Update key 'GetEventsFromDays' to the specify the historical events to be retrieved in Splunk in number of days from the current date. Default this will get events before 90 days from the current date. This is the max days that SCWA the history of events.
	e.g. Setting 'GetEventsFromDays=5' will get 5 days of historical events from the current date.
	e.g. Setting 'GetEventsFromDays=30' will get 30 days of historical events from the current date.
5. Install Splunk if not already installed.
6. Copy 'splunklib' folder to '$SPLUNK_HOME/bin/scripts/'.
7. Login to the splunk Server instance/VM and update the permissions to copy scripts at location  '/opt/splunk/bin/scripts'.
8. Copy script and configuration files 'ScwaGetEvents.py', 'ScwaGetEventsConfig.ini' and 'ScwaGetEventsStatus.status' on Splunk Server to locations '/opt/splunk/bin/scripts' (if Splunk is on Windows then 'C:\Program Files\Splunk\bin\scripts') directory.
Run the following commands to provide permissions to splunk user to execute scripts,
	e.g. If splunk user of splunk group is owner of splunk exeute following commands:- 
	chown splunk:splunk /opt/splunk/bin/scripts/ScwaGetEvents*
	chmod u=rx /opt/splunk/bin/scripts/ScwaGetEvents.py
	chmod u=rw /opt/splunk/bin/scripts/ScwaGetEventsStatus.status
9. Login to Splunk portal.
10. Goto, Settings → Data Inputs → Scripts → New
	a) Select 'Script Path' as '$SPLUNK_HOME/bin/scripts'
	b) Select 'Script Name' as 'ScwaGetEvents.py'
	c) Select 'Command' as '$SPLUNK_HOME/bin/scripts/ScwaGetEvents.py'
	d) Select 'Interval Input' as 'In Seconds' (You can select 'Cron Schedule' as well if you are comfortable)
	e) Type 'Interval' as '86400' (i.e. seconds in day) (Cron expression as appropriate if you have selected 'Cron Schedule' above) Recommendation is to have difference of a day between the schedules as sometimes this may take longer when you configure it to retrieve historical data.
	f) You may want to specify an appropriate 'Source name override' value.
11. Click 'Next'
	a) Select 'Source Type' as 'Structured' → '_json'
	b) Select 'App context' as 'Search & Reporting'
	c) Provide appropriate 'Host field value'
	d) Select or create new index as appropriate.
12. Click 'Review' to review configurations and 'Submit'.
13. You should be able start receiving the SCWA events in Splunk.
