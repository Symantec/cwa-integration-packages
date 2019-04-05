# Cloud Workload Assurance integration with Jira ticketing system. 
The integration enables you to open Jira tickets for failed checks for manual remediation.

# Prerequisites for CWA integration with Jira
 1. Install Python 3.7 or above
 2. Import Python Jira Library

# Steps to implement the Jira integration
 1. Download CWA_Jira_integration.zip
 The zip file contains the following two files:
	JiraTicketsCWAEvents.py
	JiraTicketsCWAEventsCongif.ini
2. Open JiraTicketsCWAEventsCongif.ini and provide values for the following fields:
	Credentials - Client_ID (You can get this value from the CWA console.)
		      Client_Secret (You can get this value from the CWA console.)
	
	JiraConfiguration - JiraUrl (Your orgnaization's Jira URL)
			  - JiraUserName (FirstName_LastName)
			  - JiraUserPassword (Refer to   "https://www.base64encode.net/")
			  - JiraProjectID (Refer to  "https://confluence.atlassian.com/jirakb/how-to-get-project-id-from-the-jira-user-                                           interface-827341414.html")
 
			  - JiraAssigneeUser (Users to whom the Jira tickets are assigned) (FirstName_LastName)
	
	Events - EventTypeFilter (filters events of specific event type for which you want to create Jira ticket.)
	       - EventsType = Compliance Check
	       - GetEventsFromDays = 1
3. Set up a cron job for the script to run once a day.

			    		    		


-----------------------------------------------------------------------------------------------------------------------------
Copyright � 2019 Symantec Corporation. All rights reserved.

Symantec, the Symantec Logo, the Checkmark Logo and  are trademarks or registered trademarks of Symantec Corporation or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners.

This Symantec product may contain third party software for which Symantec is required to provide attribution to the third party (�Third Party Programs�). Some of the Third Party Programs are available under open source or free software licenses. The License Agreement accompanying the Software does not alter any rights or obligations you may have under those open source or free software licenses. Please see the Third Party Legal Notice Appendix to this Documentation or TPIP ReadMe File accompanying this Symantec product for more information on the Third Party Programs.

The product described in this document is distributed under licenses restricting its use, copying, distribution, and decompilation/reverse engineering. No part of this document may be reproduced in any form by any means without prior written authorization of Symantec Corporation and its licensors, if any.

THE DOCUMENTATION IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID. SYMANTEC CORPORATION SHALL NOT BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES IN CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS DOCUMENTATION. THE INFORMATION CONTAINED IN THIS DOCUMENTATION IS SUBJECT TO CHANGE WITHOUT NOTICE.

The Licensed Software and Documentation are deemed to be commercial computer software as defined in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and DFARS 227.7202, et seq. "Commercial Computer Software and Commercial Computer Software Documentation," as applicable, and any successor regulations, whether delivered by Symantec as on premises or hosted services. Any use, modification, reproduction release, performance, display or disclosure of the Licensed Software and Documentation by the U.S. Government shall be solely in accordance with the terms of this Agreement.

Symantec Corporation
350 Ellis Street
Mountain View, CA 94043
https://www.symantec.com
