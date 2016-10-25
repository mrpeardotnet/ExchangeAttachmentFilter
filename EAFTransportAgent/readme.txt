EAFTransportAgent: Exchange 2010 Transport Protocol Agent
=========================================================

Introduction
------------

EAFTransportAgent (ExchangeAttachmentFilter Transport Agent) is an Exchange (2010)
Transport Protocol Agent.

EAFTransportAgent detects potentially dangerous attachments by scaning attachment file names (not contents).
But can scan archive contents (ZIP files) for such potentially dangerous file names and is able to scan
OpenXML documents (Office 2007 and newer) and detect macro enabled documents.

EAFTransportAgent is security extension for Exchange servers that can be used to block or remove 
potentially dangerous attachments, such as executables, javascript files, macro enabled office 
documents and many others. 

EAFTransportAgent is supposed to be used as basic antivirus solution that will increase security of your 
Excgange server easily and with no costs.

EAFTransportAgent is widely configurable via config.xml file and can be tweaked to suit your configuration
needs. 

EAFTransportAgent can be configured to log useful information about messages and attachments passing 
your Exchange server. These logs are stored as human readable text files so you can easily and immediately 
understand what kind of messages and how they has been processed by your server use it to fine tune your configuration.


Configuration
-------------

The configuration is stored in file called config.xml and this file must placed at the same location of the agent's
assembly (DLL).

Configuration file is divided to sections:

    <attachments> section
        the lists of filenames (using wildcards) to reject, remove or whitelist are defined here
    <parameters> section
        EAFTransportAgent parameters are defined here
    <senders> section
        Senders (email addresses) can be whitelisted in this section.

There is default config.xml file included in this project. Please review this sample configuration and read
comments to better understand configuration options. You can change configuration on thy fly, the agent
detects config.xml changes and reload configuration on it's every change.


Installation Steps
------------------
You need access to Exchange Management Shell to install and configure (any) Exchange Ttransport Agent.
Here are recommended steps to install EAFTransportAgent:

1. Create a directory on your Exchange Server, for example:
    C:\EAF

2. Unzip the EAFTransportAgent.zip file in that directory (files EAFTransportAgent.dll, ICSharpCode.SharpZipLib.dll and config.xml).

3. Edit the config.xml according to your needs

4. Open the Exchange Management Shell and run the following command to install the agent, assuming the 
   directory with the AttachmentFilter Agent is 'C:\EAF':
   
[PS] C:\>install-transportagent -Name "AttachmentFilter Agent" -TransportAgentFactory:MrPear.Net.ExchangeAttachmentFilter.ExchangeAttachmentFilterFactory -AssemblyPath:"C:\EAF\EAFTransportAgent.dll"

Identity                                           Enabled         Priority
--------                                           -------         --------
AttachmentFilter Agent                             False           10

WARNING: Please exit Powershell to complete the installation.
WARNING: The following service restart is required for the change(s) to take effect : MSExchangeTransport

NOTE: If you have problems installing Transport Agent getting, try reseting IIS using 'iisreset':

[PS] C:\>iisreset

5. Now the priority of the AttachmentFilter Agent should be adjusted.
   Setting the priority AFTER Connection Filtering Agent AND BEFORE Content Filter Agent and Recipient Filter Agent is recommended. 
   For example, if you would set EAFTransportAgent priority after the Content Filter Agent or Recipient Filter Agent then 
   messages rejected by those two transport agents won't be procesed by EAFTransportAgent.
   
   So you first need to figure that out priority of all installed Transport Agents by using the get-transportagent task:

[PS] C:\>get-transportagent

Identity                                           Enabled         Priority
--------                                           -------         --------
Transport Rule Agent                               True            1
Text Messaging Routing Agent                       True            2
Text Messaging Delivery Agent                      True            3
Connection Filtering Agent                         True            4
Sender Id Agent                                    True            5
Content Filter Agent                               True            6
Sender Filter Agent                                True            7
Recipient Filter Agent                             True            8
Protocol Analysis Agent                            True            9
AttachmentFilter Agent                             True            10

So in this case the priority of the Connection Filtering Agent is 4 so it is recommended to set EAFTransportAgent
priorty to 5.

[PS] C:\>Set-TransportAgent "AttachmentFilter Agent" -priority 5

WARNING: The following service restart is required for the change(s) to take effect : MSExchangeTransport

6. Now the agent must be enabled:

[PS] C:\>enable-transportagent "AttachmentFilter Agent"

WARNING: The following service restart is required for the change(s) to take effect : MSExchangeTransport

7. Now it is time to restart the Transport service:

[PS] C:\>Restart-Service MSExchangeTransport

Uninstall Transport Agent
-------------------------
If you need for any reason to uninstall EAFTransportAgent, you can use this command:

[PS] C:\>uninstall-transportagent "AttachmentFilter Agent"

And don't forget to restart the Transport service.


EAFTransportAgent logs
----------------------
If enabled (yes by default), logs are created in folder Logs that is created in the same location as the agent's dll. Single log file
is created for every single day and no log files are deleted by the agent so it is recommended to remove old log files manually.

