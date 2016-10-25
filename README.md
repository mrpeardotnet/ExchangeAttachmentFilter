# ExchangeAttachmentFilter Transport Agent

EAFTransportAgent (ExchangeAttachmentFilter Transport Agent) is an Exchange (2010)
Transport Protocol Agent.

## Overview
EAFTransportAgent detects potentially dangerous attachments by scaning attachment file names (not contents).
As advanced feature it can scan archive contents (ZIP files) for such potentially dangerous file names 
and it is also able to scan OpenXML documents (Office 2007 and newer) and detect macro enabled documents.

## What is it supposed to do
EAFTransportAgent is security extension for Exchange servers that can be used to block or remove 
potentially dangerous attachments, such as executables, javascript files, macro enabled office 
documents and many others. 

EAFTransportAgent is supposed to be used as basic antivirus solution that will increase security of your 
Excgange server easily and with no costs.

## Configuration options
EAFTransportAgent is widely configurable via config.xml file and can be tweaked to suit your configuration
needs. 

## Logging
EAFTransportAgent can be configured to log useful information about messages and attachments passing 
your Exchange server. These logs are stored as human readable text files so you can easily and immediately 
understand what kind of messages and how they has been processed by your server use it to fine tune your configuration.
