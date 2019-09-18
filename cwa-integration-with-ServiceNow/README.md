#### Cloud Workload Assurance integration with ServiceNow (SNOW) ticketing system. 
The integration enables you to open ServiceNow tickets for failed checks for manual remediation.

 Prerequisites for CWA integration with ServiceNow
 1. Install Python 3.7 or above
 2. Import ServiceNow Library pysnow (https://pysnow.readthedocs.io/en/latest/general.html#installing)

 Steps to implement the ServiceNow integration
 1. Download cwa-integration-with-ServcieNow packages
 The package contains the following two files:
	  * SNOWTicketsCWAEvents.py
	  * SNOWTicketsCWAEventsConfig.ini
 2. Open SNOWTicketsCWAEventsConfig.ini and provide values for the following fields:
	  * `Credentials`
    * `CLIENT_ID (You can get this value from the CWA console.)`
    * `CLIENT_SECRET You can get this value from the CWA console.)`
	
	 * `SNOWConfiguration`
    * `SNOWInstance` 
    * `SNOWUserName` 
    * `SNOWPassword` (Base 64 encoded password, Refer to "https://www.base64encode.net/")
    * `SNOWSummaryFieldLimit (The character limit of summary filed of SNOW incidents)`
 3. Set up a cron job for the script to run once a day.


----------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------
PYSNOW - ServiceNow HTTP client library written in Python
			    		    		
MIT License

Copyright (c) 2018 Robert Wikman <rbw@vault13.org>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ìSoftwareî), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED ìAS ISî, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Copyright © 2019 Symantec Corporation. All rights reserved.

Symantec, the Symantec Logo, the Checkmark Logo and  are trademarks or registered trademarks of Symantec Corporation or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners.

This Symantec product may contain third party software for which Symantec is required to provide attribution to the third party (ìThird Party Programsî). Some of the Third Party Programs are available under open source or free software licenses. The License Agreement accompanying the Software does not alter any rights or obligations you may have under those open source or free software licenses. Please see the Third Party Legal Notice Appendix to this Documentation or TPIP ReadMe File accompanying this Symantec product for more information on the Third Party Programs.

The product described in this document is distributed under licenses restricting its use, copying, distribution, and decompilation/reverse engineering. No part of this document may be reproduced in any form by any means without prior written authorization of Symantec Corporation and its licensors, if any.

THE DOCUMENTATION IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID. SYMANTEC CORPORATION SHALL NOT BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES IN CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS DOCUMENTATION. THE INFORMATION CONTAINED IN THIS DOCUMENTATION IS SUBJECT TO CHANGE WITHOUT NOTICE.

The Licensed Software and Documentation are deemed to be commercial computer software as defined in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and DFARS 227.7202, et seq. "Commercial Computer Software and Commercial Computer Software Documentation," as applicable, and any successor regulations, whether delivered by Symantec as on premises or hosted services. Any use, modification, reproduction release, performance, display or disclosure of the Licensed Software and Documentation by the U.S. Government shall be solely in accordance with the terms of this Agreement.

Symantec Corporation
350 Ellis Street
Mountain View, CA 94043
https://www.symantec.com
