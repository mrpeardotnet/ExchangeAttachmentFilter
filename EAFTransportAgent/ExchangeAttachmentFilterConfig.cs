using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Threading;
using System.Xml.Linq;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    /// <summary>
    /// Configuration wrapper exposing configuration properties to be used in transport agent.
    /// Loads and parses configuration from configuration XML file.
    /// Watches last write attribute and forces config reload when config file has changed.
    /// </summary>
    public class ExchangeAttachmentFilterConfig
    {
        private readonly string _configDirectory;
        private int _configIsReloading = 0;

        public ExchangeAttachmentFilterConfig()
        {
            // get config directory (the same as agent's dll dir)
            _configDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            if (_configDirectory == null)
            {
                SysLog.Log("Config ERROR: Config directory is NULL.");
                return;
            }
            var configFileWatcher = new FileSystemWatcher(_configDirectory)
            {
                NotifyFilter = NotifyFilters.LastWrite,
                Filter = Config.ConfigFileName
            };
            configFileWatcher.Changed += ConfigFileWatcherOnChanged;
            // Load configuration
            LoadConfig();

            // Start config file monitoring
            configFileWatcher.EnableRaisingEvents = true;
        }

        private void ConfigFileWatcherOnChanged(object sender, FileSystemEventArgs fileSystemEventArgs)
        {
            // Ignore if load ongoing
            if (Interlocked.CompareExchange(ref _configIsReloading, 1, 0) != 0)
            {
                SysLog.Log("Config already loading...");
                return;
            }
            LoadConfig();
        }

        /// <summary>
        /// Loads XML configuration file and sets up exposed configuration properties.
        /// </summary>
        private void LoadConfig()
        {
            try
            {
                var xDocPath = Path.Combine(_configDirectory, Config.ConfigFileName);
                if (!File.Exists(xDocPath))
                {
                    throw new Exception($"Config file not found ({xDocPath}).");
                }

                // parse config xml file
                var xDoc =
                    XDocument.Load(
                        new StreamReader(new FileStream(xDocPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)));
                var root = xDoc.Root;
                if (root == null)
                    throw new XmlSyntaxException("Invalid XML configuration.");
                var attachments = root.Element("attachments");
                if (attachments != null)
                {
                    AttachmentsWhitelist =
                        attachments.Element("whitelist")?.Elements("attachment").Select(e => e.Value).ToList();
                    AttachmentsRemove =
                        attachments.Element("remove")?.Elements("attachment").Select(e => e.Value).ToList();
                    AttachmentsReject =
                        attachments.Element("reject")?.Elements("attachment").Select(e => e.Value).ToList();
                }
                var senders = root.Element("senders");
                if (senders != null)
                {
                    SendersWhitelist =
                        senders.Element("whitelist")?.Elements("sender").Select(e => e.Value).ToList();
                }
                var parameters = root.Element("parameters");
                if (parameters == null)
                    return;
                ScanArchives = GetParameterValueAsBool(parameters, "scanArchives", Config.ScanArchivesDefault);
                DsnStripOriginalMessage = GetParameterValueAsBool(parameters, "dsnStripOriginalMessage",
                    Config.DsnStripOriginalMessageDefault);
                LogRejectedOrRemoved = GetParameterValueAsBool(parameters, "logRejectedOrRemoved",
                    Config.LogRejectedOrRemovedDefault);
                LogAccepted = GetParameterValueAsBool(parameters, "logAccepted",
                    Config.LogAcceptedDefault);
                RemovedAttachmentPrefix = GetParameterValue(parameters, "removedAttachmentPrefix",
                    Config.RemovedAttachmentPrefixDefault);
                RemovedAttachmentNewContent =
                    GetParameterValue(parameters, "removedAttachmentNewContent",
                        Config.RemovedAttachmentNewContentDefault).Replace(@"\r\n", Environment.NewLine);
            }
            catch (Exception ex)
            {
                SysLog.Log("LoadConfig ERROR: " + ex.Message);
            }
            _configIsReloading = 0;
        }

        /// <summary>
        /// Gets XML configuration parameter value as string.
        /// </summary>
        /// <param name="parametersElement">Root container element with 'parameter' nodes.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <param name="defaultValue">Default value returned if the parameter name is not found.</param>
        /// <returns>Parameter value as string.</returns>
        private static string GetParameterValue(XContainer parametersElement, string parameterName, string defaultValue)
        {
            var parameterElement = parametersElement.Elements("parameter").FirstOrDefault(x =>
            {
                var xAttribute = x.Attribute("name");
                return xAttribute != null && xAttribute.Value.ToLower().Equals(parameterName.ToLower());
            });
            
            return parameterElement != null ? parameterElement.Value : defaultValue;
        }

        /// <summary>
        /// Gets XML configuration parameter value as boolean.
        /// </summary>
        /// <param name="parametersElement">Root container element with 'parameter' nodes.</param>
        /// <param name="parameterName">Name of the parameter.</param>
        /// <param name="defaultValue">Default value returned if the parameter name is not found.</param>
        /// <returns>Parameter value as boolean.</returns>
        private static bool GetParameterValueAsBool(XContainer parametersElement, string parameterName, bool defaultValue)
        {
            return GetParameterValue(parametersElement, parameterName, defaultValue ? "1" : "0").Trim().Equals("1");
        }

        // parameters
        public bool ScanArchives { get; private set; } = Config.ScanArchivesDefault;
        public bool ScanOpenXmlDocuments { get; private set; } = Config.ScanOpenXmlDocumentsDefault;
        public bool DsnStripOriginalMessage { get; private set; } = Config.DsnStripOriginalMessageDefault;
        public bool LogRejectedOrRemoved { get; private set; } = Config.LogRejectedOrRemovedDefault;
        public bool LogAccepted { get; private set; } = Config.LogAcceptedDefault;
        public string RemovedAttachmentPrefix { get; private set; } = Config.RemovedAttachmentPrefixDefault;
        public string RemovedAttachmentNewContent { get; private set; } = Config.RemovedAttachmentNewContentDefault;

        // lists
        public IEnumerable<string> AttachmentsWhitelist { get; private set; } = new List<string>();
        public IEnumerable<string> AttachmentsRemove { get; private set; } = new List<string>();
        public IEnumerable<string> AttachmentsReject { get; private set; } = new List<string>();
        public IEnumerable<string> SendersWhitelist { get; private set; } = new List<string>();
    }
}
