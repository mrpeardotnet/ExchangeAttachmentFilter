/* ExchangeAttachmentFilterRoutingAgent
 * ====================================
 * Exchange attachment filter (for Exchange 2010)
 * 
 * by mrpear.net (2016)
 * http://mrpear.net
 * 
 * This transport agent (designed for Exchange 2010) scans attachments file names and removes
 * potentially dangerous ones or completely rejects the whole message (depending on configuration).
 * 
 * It uses SharpZipLib to process ZIP file entries to scan file names inside archives, too.
 * This is not native Exchange 2010 functionality and you cannot block such attachments easily.
 * And this is why this TransportAgent was created.
 * 
 
 * This agent can be used as simple antivirus solution for all who does not have full featured AV.
 * 
 * SharpZipLib soure:
 * https://icsharpcode.github.io/SharpZipLib/
 * 
 * 
 * Released under GNU license, feel free to use this code to learn something 
 * or just modify it for your needs.
 *
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using ICSharpCode.SharpZipLib.Zip;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Email;
using Microsoft.Exchange.Data.Transport.Routing;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    public class ExchangeAttachmentFilterRoutingAgent : RoutingAgent
    {
        private const int StatusTagAcceptNoMatch = 0;
        private const int StatusTagAcceptWhitelist = 1;

        private readonly object _fileLock = new object();

        private readonly ExchangeAttachmentFilterConfig _exchangeAttachmentFilterConfig;
        public ExchangeAttachmentFilterRoutingAgent(ExchangeAttachmentFilterConfig exchangeAttachmentFilterConfig)
        {
            _exchangeAttachmentFilterConfig = exchangeAttachmentFilterConfig;
            OnRoutedMessage += ExchangeAttachmentFilterRoutingAgent_OnRoutedMessage;
            OnSubmittedMessage += OnOnSubmittedMessage;
        }

        private void OnOnSubmittedMessage(SubmittedMessageEventSource source, QueuedMessageEventArgs queuedMessageEventArgs)
        {
            lock (_fileLock)
            {
                AgentAsyncContext agentAsyncContext = null;
                try
                {
                    var mailItem = queuedMessageEventArgs.MailItem;
                    agentAsyncContext = GetAgentAsyncContext();

                    // check the sender whitelist
                    if (_exchangeAttachmentFilterConfig.SendersWhitelist.Any(
                        f => Regex.IsMatch(mailItem.FromAddress.ToString(), WildcardToRegex(f))))
                        return;

                    // maybe we will need list of recipients on single line...
                    var recipientList = new StringBuilder();
                    for (var i = 0; i < mailItem.Recipients.Count; i++)
                    {
                        recipientList.Append(i == 0 ? mailItem.Recipients[i].Address.ToString() : "; " + mailItem.Recipients[i].Address);
                    }

                    var removedAttachments = new List<Attachment>();
                    var strippedAttachments = new List<Attachment>();
                    var messageRejected = false;

                    var messageLogStringBuilder = new SysLogBuilder();

                    var mailItemStatusText =
                        $"[from: {mailItem.FromAddress}] [to: {recipientList}] [method: {mailItem.InboundDeliveryMethod}] [subject: {mailItem.Message.Subject}] [size: {mailItem.MimeStreamLength.ToString("N0")}]";
                    messageLogStringBuilder.Log(mailItemStatusText);

                    if (_exchangeAttachmentFilterConfig.MailSizeThreshold > 0 && (mailItem.MimeStreamLength/1024 > _exchangeAttachmentFilterConfig.MailSizeThreshold))
                    {
                        messageLogStringBuilder.LogPadded("ACCEPTED: [reason: mail size threshold]");
                    }
                    else
                    {
                        if (_exchangeAttachmentFilterConfig.MailboxMethodSafe &&
                            mailItem.InboundDeliveryMethod == DeliveryMethod.Mailbox)
                        {
                            messageLogStringBuilder.LogPadded(
                                "ACCEPTED: [reason: Inbound Delivery Method Safe (Mailbox)]");
                        }
                        else
                        {
                            if (mailItem.Message.Attachments.Count == 0 && _exchangeAttachmentFilterConfig.LogAccepted)
                            {
                                messageLogStringBuilder.LogPadded("ACCEPTED: [reason: no attachments]");
                            }
                            else
                            {
                                foreach (var attachment in mailItem.Message.Attachments)
                                {
                                    // It would be great idea to process only attachments with size greater 
                                    // than some threshold, 'cos infected files are always quite small (only few kB)
                                    // But I am not sure how to get the attachment size here, ...

                                    // if (any previous) attachment rejected the message then break the processing now 
                                    if (messageRejected)
                                        break;

                                    AttachmentFilterStatus attachmentStatus = null;

                                    if (_exchangeAttachmentFilterConfig.DsnStripOriginalMessage)
                                    {
                                        // DSN has InboundDeliveryMethod equal to DeliveryMethod.File and FromAddress is equal to <>
                                        // and DSN's original message is included as message/rfc822 attachment
                                        if (mailItem.InboundDeliveryMethod == DeliveryMethod.File &&
                                            mailItem.FromAddress.ToString() == "<>" &&
                                            attachment.ContentType.ToLower().Equals("message/rfc822"))
                                        {
                                            attachmentStatus =
                                                new AttachmentFilterStatus(AttachmentFilterStatusEnum.StripAttachment,
                                                    "DSN original message");
                                        }
                                    }

                                    if (attachmentStatus == null)
                                    {
                                        // default file status (by extension)
                                        attachmentStatus = FilenameFilterStatus(attachment.FileName);

                                        // do not process whitelisted attachments, so check the filename filter result
                                        if (!(attachmentStatus.Status == AttachmentFilterStatusEnum.Accept &&
                                              attachmentStatus.StatusTag == StatusTagAcceptWhitelist))
                                        {
                                            // is it archive?
                                            if (_exchangeAttachmentFilterConfig.ScanArchives &&
                                                IsArchive(attachment.FileName))
                                            {
                                                var archiveStatus =
                                                    ProcessArchiveStream(attachment.GetContentReadStream());
                                                if (archiveStatus.Status > attachmentStatus.Status)
                                                    attachmentStatus = archiveStatus;
                                            }

                                            // is it OpenXml document?
                                            if (_exchangeAttachmentFilterConfig.ScanOpenXmlDocuments &&
                                                IsOpenXmlDocument(attachment.FileName))
                                            {
                                                var openXmlDocumentStatus =
                                                    ProcessOpenXmlDocumentStream(attachment.GetContentReadStream());
                                                if (openXmlDocumentStatus.Status > attachmentStatus.Status)
                                                    attachmentStatus = openXmlDocumentStatus;
                                            }

                                            // is it html attachment (remove)?
                                            if (_exchangeAttachmentFilterConfig.RemoveHtmlAttachmentsWithScripts &&
                                                IsHtmlAttachment(attachment.FileName))
                                            {
                                                // check for script tags
                                                attachmentStatus =
                                                    new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept,
                                                        "HTML/No scripts");
                                                if (CheckHtmlForScriptTags(attachment.GetContentReadStream()))
                                                    attachmentStatus =
                                                        new AttachmentFilterStatus(
                                                            AttachmentFilterStatusEnum.RemoveAttachment,
                                                            "HTML/Script tag(s) found");
                                            }
                                        }
                                    }

                                    var attachmentStatusText =
                                        $"[file: {attachment.FileName}] [type: {attachment.AttachmentType}] [content type:{attachment.ContentType}] [reason: {attachmentStatus.Reason}]";

                                    switch (attachmentStatus.Status)
                                    {
                                        case AttachmentFilterStatusEnum.Accept:
                                            if (_exchangeAttachmentFilterConfig.LogAccepted)
                                            {
                                                messageLogStringBuilder.LogPadded($"ACCEPTED: {attachmentStatusText}");
                                            }
                                            break;
                                        case AttachmentFilterStatusEnum.RemoveAttachment:
                                            // just mark this attachment for removement, but do not touch attachments collection now
                                            // (we are in foreach loop and need to process them all)
                                            removedAttachments.Add(attachment);
                                            if (_exchangeAttachmentFilterConfig.LogRejectedOrRemoved)
                                            {
                                                messageLogStringBuilder.LogPadded($"REMOVED: {attachmentStatusText}");
                                            }
                                            break;
                                        case AttachmentFilterStatusEnum.StripAttachment:
                                            // just mark this attachment for removement, but do not touch attachments collection now
                                            // (we are in foreach loop and need to process them all)
                                            strippedAttachments.Add(attachment);
                                            if (_exchangeAttachmentFilterConfig.LogRejectedOrRemoved)
                                            {
                                                messageLogStringBuilder.LogPadded($"STRIPPED: {attachmentStatusText}");
                                            }
                                            break;
                                        case AttachmentFilterStatusEnum.RejectMessage:
                                            // reject whole message
                                            if (_exchangeAttachmentFilterConfig.LogRejectedOrRemoved)
                                            {
                                                messageLogStringBuilder.LogPadded($"REJECTED: {attachmentStatusText}");
                                            }
                                            messageRejected = true;
                                            break;
                                        default:
                                            messageLogStringBuilder.LogPadded(
                                                $"UNKNOWN STATUS: {attachmentStatusText}");
                                            break;
                                    }
                                }
                            }
                        }
                    }

                    if (messageLogStringBuilder.MessageCount > 1)
                        SysLog.Log(messageLogStringBuilder);

                    // reject the message?
                    if (messageRejected)
                    {
                        // delete the source message and do nothing more (we do not send DSN)...
                        source.Delete();
                        return;
                    }

                    // for every attachment we marked as being removed create new txt attachment with some info why it happened...
                    foreach (var removedAttachment in removedAttachments)
                    {
                        // new attachment filename
                        var newFileName = $"{_exchangeAttachmentFilterConfig.RemovedAttachmentPrefix}{removedAttachment.FileName}.txt";
                        // add new attachment to the message...
                        var newAttachment = mailItem.Message.Attachments.Add(newFileName);
                        // ...and write content into it (info message)
                        var newAttachmentWriter = new StreamWriter(newAttachment.GetContentWriteStream());
                        newAttachmentWriter.WriteLine(removedAttachment.FileName);
                        newAttachmentWriter.WriteLine();
                        newAttachmentWriter.WriteLine(_exchangeAttachmentFilterConfig.RemovedAttachmentNewContent);
                        newAttachmentWriter.Flush();
                        newAttachmentWriter.Close();
                    }

                    // finally remove all attachments marked for removal
                    foreach (var removedAttachment in removedAttachments)
                    {
                        mailItem.Message.Attachments.Remove(removedAttachment);
                    }

                    // ...and stripped attachments, too
                    foreach (var strippedAttachment in strippedAttachments)
                    {
                        mailItem.Message.Attachments.Remove(strippedAttachment);
                    }
                }
                catch (IOException ex)
                {
                    SysLog.Log("IOException: " + ex.Message);
                }
                catch (Exception ex)
                {
                    SysLog.Log("Exception: " + ex.Message);
                }
                finally
                {
                    agentAsyncContext?.Complete();
                }
            }
        }

        private void ExchangeAttachmentFilterRoutingAgent_OnRoutedMessage(RoutedMessageEventSource source, QueuedMessageEventArgs e)
        {
        }

        /// <summary>
        /// Check given file name against attachment lists and return check result.
        /// </summary>
        /// <param name="fileName">File name to check.</param>
        /// <returns>Status of the file name (accept, remove, reject)</returns>
        public AttachmentFilterStatus FilenameFilterStatus(string fileName)
        {
            // whitelisted
            if (_exchangeAttachmentFilterConfig.AttachmentsWhitelist.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f))))
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept, StatusTagAcceptWhitelist, "Filename WHITELIST");

            // remove attachment
            if (_exchangeAttachmentFilterConfig.AttachmentsRemove.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f))))
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.RemoveAttachment, "Filename REMOVE");

            // reject attachment
            if (_exchangeAttachmentFilterConfig.AttachmentsReject.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f))))
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.RejectMessage, "Filename REJECT");

            return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept, StatusTagAcceptNoMatch, "No match");
        }

        /// <summary>
        /// Processes input stream as Open XML document checks if macro enabled.
        /// This method will copy source stream contents into new memory stream if the source stream is not seekable.
        /// </summary>
        /// <remarks>Calls itself recursively when another archive is found in current archive.</remarks>
        /// <param name="openXmlDocumentStream">Stream containing OpenXML document data.</param>
        /// <returns></returns>
        public static AttachmentFilterStatus ProcessOpenXmlDocumentStream(Stream openXmlDocumentStream)
        {
            // OpenXml is just ZIPed file, try to get inside
            try
            {
                // we need seekable stream to check it's contents (zip lib)
                if (openXmlDocumentStream.CanSeek)
                    return ProcessOpenXmlDocumentStreamContents(openXmlDocumentStream);

                // no seekable stream, so let's copy it to the new memory stream
                using (var memoryStream = new MemoryStream())
                {
                    var buffer = new byte[32768];
                    int read;
                    while ((read = openXmlDocumentStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        memoryStream.Write(buffer, 0, read);
                    }
                    memoryStream.Position = 0;
                    return ProcessOpenXmlDocumentStreamContents(memoryStream);
                }
            }
            catch (ZipException ex)
            {
                // does not look like zip so we will accept it (it is not open XML file)
                //SysLog.Log($"OpenXml Zip/ERROR [{ex.GetType()}]: {ex.Message}");
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept, $"OpenXml ERROR [{ex.GetType()}]: {ex.Message}");
            }
            catch (Exception ex)
            {
                // generic error, remove it
                SysLog.Log($"OpenXml ERROR [{ex.GetType()}]: {ex.Message}");
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.RemoveAttachment, $"OpenXml ERROR [{ex.GetType()}]: {ex.Message}");
            }
        }

        /// <summary>
        /// Processes input stream as Open XML document checks if macro enabled.
        /// Requires source stream to be seekable, otherwise will throw an exception.
        /// </summary>
        /// <param name="openXmlDocumentStream"></param>
        /// <returns></returns>
        private static AttachmentFilterStatus ProcessOpenXmlDocumentStreamContents(Stream openXmlDocumentStream)
        {
            using (var zipFile = new ZipFile(openXmlDocumentStream))
            {
                var contentTypesEntry = zipFile.GetEntry("[Content_Types].xml");
                if (contentTypesEntry == null)
                    return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept,
                        "OpenXml \"[Content_Types].xml\" not found");
                var contentTypesEntryStream = zipFile.GetInputStream(contentTypesEntry);
                var xDoc = XDocument.Load(new XmlTextReader(contentTypesEntryStream));
                var rootElement = xDoc.Root;
                if (rootElement == null)
                    return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept,
                        "OpenXml root element \"Types\" not found.");
                if (!rootElement.Name.LocalName.ToLower().Equals("types"))
                    return new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept,
                        $"OpenXml root element mismatch (found: {rootElement.Name.LocalName}, expected: Types");

                // Try to find macroEnabled content type => reject this kind of files
                var type = rootElement.Elements().FirstOrDefault(x =>
                {
                    var typeContentTypeAttribute = x.Attribute("ContentType");
                    return typeContentTypeAttribute != null &&
                           typeContentTypeAttribute.Value.ToLower().Contains("macroenabled");
                });

                return type == null
                    ? new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept, "OpenXml OK")
                    : new AttachmentFilterStatus(AttachmentFilterStatusEnum.RejectMessage,
                        "OpenXml macroEnabled");
            }
        }

        /// <summary>
        /// Processes input stream as archive and scans archive file entries (checks the archive contents).
        /// </summary>
        /// <remarks>Calls itself recursively when another archive is found in current archive.</remarks>
        /// <param name="archiveStream">Stream containing archive data.</param>
        /// <returns></returns>
        public AttachmentFilterStatus ProcessArchiveStream(Stream archiveStream)
        {
            var result = new AttachmentFilterStatus(AttachmentFilterStatusEnum.Accept, "Archive OK");
            try
            {
                using (var zipFile = new ZipFile(archiveStream))
                {
                    foreach (ZipEntry entry in zipFile)
                    {
                        var fileResult = FilenameFilterStatus(entry.Name);
                        if (fileResult.Status > result.Status)
                            result = fileResult;
                        if (IsArchive(entry.Name))
                        {
                            var archiveResult = ProcessArchiveStream(zipFile.GetInputStream(entry));
                            if (archiveResult.Status > result.Status)
                                result = archiveResult;
                        }
                        if (IsOpenXmlDocument(entry.Name))
                        {
                            var openXmlDocumentStatus = ProcessOpenXmlDocumentStream(zipFile.GetInputStream(entry));
                            if (openXmlDocumentStatus.Status > result.Status)
                                result = openXmlDocumentStatus;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Processing usually fails because of:
                //   - password protected archive (when we need to access it's contents)
                //   - unsupported archive (version, format, ...)
                //   - corrupted archive
                //   - spoofed file extension (looks like some kind of archive but it is of different type)

                // We remove such attchments (recommended, might be dangerous, maybe not... just let the recipient know)
                SysLog.Log($"Archive ERROR [{ex.GetType()}]: {ex.Message}");
                return new AttachmentFilterStatus(AttachmentFilterStatusEnum.RemoveAttachment, $"Archive ERROR [{ex.GetType()}]: {ex.Message}");
            }
            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="attachmentStream"></param>
        /// <returns></returns>
        public bool CheckHtmlForScriptTags(Stream attachmentStream)
        {
            try
            {
                using (var fileStream = new StreamReader(attachmentStream))
                {
                    var htmlData = fileStream.ReadToEnd();
                    return Regex.IsMatch(htmlData, @"<script[\s\S]*?>[\s\S]*?<\/script>", RegexOptions.IgnoreCase);
                }
            }
            catch (Exception ex)
            {
                SysLog.Log($"HTML ERROR [{ex.GetType()}]: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Checks if the filename is archive (by file extension).
        /// </summary>
        /// <param name="fileName">File name to check.</param>
        /// <returns>Returns true if the filename is archive.</returns>
        public static bool IsArchive(string fileName)
        {
            return Config.ArchiveFileTypes.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f)));
        }

        /// <summary>
        /// Checks if the filename is open XML document (by file extension).
        /// </summary>
        /// <param name="fileName">Filename to check.</param>
        /// <returns></returns>
        public static bool IsOpenXmlDocument(string fileName)
        {
            return Config.OpenXmlDocumentFileTypes.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f)));
        }

        /// <summary>
        /// Checks if the filename is html attachment (by file extension).
        /// </summary>
        /// <param name="fileName">Filename to check.</param>
        /// <returns></returns>
        public static bool IsHtmlAttachment(string fileName)
        {
            return Config.HtmlFileTypes.Any(f => Regex.IsMatch(fileName, WildcardToRegex(f)));
        }

        /// <summary>
        /// Converts wildcard pattern to regex string. 
        /// </summary>
        /// <param name="wildcardString">Wildcard string to convert.</param>
        /// <returns>Regex string converted from the wildcard.</returns>
        public static string WildcardToRegex(string wildcardString)
        {
            return "^" + Regex.Escape(wildcardString).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        }
    }
}
