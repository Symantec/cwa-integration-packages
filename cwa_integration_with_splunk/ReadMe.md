# Cloud Workload Assurance integration with Splunk. 
The integration enables you to see compliance events on Splunk.

# Prerequisites for CWA integration with Jira
 1. Install Python 2.7 or above 
 
# Steps to configure the Splunk integration

1. Login to SCWA Portal → Settings → General Settings → API Keys. Copy CUSTOMER_ID, DOMAIN_ID, CLIENT_ID and CLIENT_SECRET values.
2. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Credentials' section. Update respective keys with the values copied in the above step.
3. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Events' section. Update key 'EventTypeFilter' with following  value: 
Compliance
 	* e.g. Setting 'EventTypeFilter=Compliance' will get Compliance events into Splunk.
4. Edit configuration file 'ScwaGetEventsConfig.ini' in 'Events' section. Update key 'GetEventsFromDays' to the specify the historical events to be retrieved in Splunk in number of days from the current date. Default this will get events before 90 days from the current date. This is the max days that SCWA the history of events.
	* e.g. Setting 'GetEventsFromDays=5' will get 5 days of historical events from the current date.
	* e.g. Setting 'GetEventsFromDays=30' will get 30 days of historical events from the current date.
5. Install Splunk if not already installed.
6. Copy 'splunklib' folder to '$SPLUNK_HOME/bin/scripts/'.
7. Login to the splunk Server instance/VM and update the permissions to copy scripts at location  '/opt/splunk/bin/scripts'.
8. Copy script and configuration files 'ScwaGetEvents.py', 'ScwaGetEventsConfig.ini' and 'ScwaGetEventsStatus.status' on Splunk Server to locations '/opt/splunk/bin/scripts' (if Splunk is on Windows then 'C:\Program Files\Splunk\bin\scripts') directory.
Run the following commands to provide permissions to splunk user to execute scripts,
	* e.g. If splunk user of splunk group is owner of splunk exeute following commands:- 
	* chown splunk:splunk /opt/splunk/bin/scripts/ScwaGetEvents*
	* chmod u=rx /opt/splunk/bin/scripts/ScwaGetEvents.py
	* chmod u=rw /opt/splunk/bin/scripts/ScwaGetEventsStatus.status
9. Login to Splunk portal.
10. Goto, Settings → Data Inputs → Scripts → New
	* Select 'Script Path' as '$SPLUNK_HOME/bin/scripts'
	* Select 'Script Name' as 'ScwaGetEvents.py'
	* Select 'Command' as '$SPLUNK_HOME/bin/scripts/ScwaGetEvents.py'
	* Select 'Interval Input' as 'In Seconds' (You can select 'Cron Schedule' as well if you are comfortable)
	* Type 'Interval' as '86400' (i.e. seconds in day) (Cron expression as appropriate if you have selected 'Cron Schedule' above) Recommendation is to have difference of a day between the schedules as sometimes this may take longer when you configure it to retrieve historical data.
	* You may want to specify an appropriate 'Source name override' value.
11. Click 'Next'
	* Select 'Source Type' as 'Structured' → '_json'
	* Select 'App context' as 'Search & Reporting'
	* Provide appropriate 'Host field value'
	* Select or create new index as appropriate.
12. Click 'Review' to review configurations and 'Submit'.
13. You should be able start receiving the SCWA events in Splunk.

Copyright © 2019 Symantec Corporation. All rights reserved.

Symantec, the Symantec Logo, the Checkmark Logo and are trademarks or registered trademarks of Symantec Corporation or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners.

This Symantec product may contain third party software for which Symantec is required to provide attribution to the third party (“Third Party Programs”). Some of the Third Party Programs are available under open source or free software licenses. The License Agreement accompanying the Software does not alter any rights or obligations you may have under those open source or free software licenses. Please see the Third Party Legal Notice Appendix to this Documentation or TPIP ReadMe File accompanying this Symantec product for more information on the Third Party Programs.

The product described in this document is distributed under licenses restricting its use, copying, distribution, and decompilation/reverse engineering. No part of this document may be reproduced in any form by any means without prior written authorization of Symantec Corporation and its licensors, if any.

THE DOCUMENTATION IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID. SYMANTEC CORPORATION SHALL NOT BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES IN CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS DOCUMENTATION. THE INFORMATION CONTAINED IN THIS DOCUMENTATION IS SUBJECT TO CHANGE WITHOUT NOTICE.

The Licensed Software and Documentation are deemed to be commercial computer software as defined in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and DFARS 227.7202, et seq. "Commercial Computer Software and Commercial Computer Software Documentation," as applicable, and any successor regulations, whether delivered by Symantec as on premises or hosted services. Any use, modification, reproduction release, performance, display or disclosure of the Licensed Software and Documentation by the U.S. Government shall be solely in accordance with the terms of this Agreement.

Symantec Corporation 350 Ellis Street Mountain View, CA 94043 https://www.symantec.com
