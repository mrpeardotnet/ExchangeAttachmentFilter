using System.Collections;
using System.Collections.Generic;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    /// <summary>
    /// Compile time configuration class including default values for configuration parameters
    /// You can change values here to suit your needs.
    /// </summary>
    public static class Config
    {
        // config file name
        public const string ConfigFileName = "config.xml";
        public const string ConfigDirectoryName = "Logs";

        // default values for parameters not found in config
        public const string RemovedAttachmentPrefixDefault = "removed_";
        public const string RemovedAttachmentNewContentDefault = "This attachment was removed for security reasons.";
        public const bool ScanArchivesDefault = true;
        public const bool ScanOpenXmlDocumentsDefault = true;
        public const bool LogRejectedOrRemovedDefault = true;
        public const bool LogAcceptedDefault = false;
        public const bool DsnStripOriginalMessageDefault = false;

        // hardcoded list of supported archive file types
        public static readonly IEnumerable<string> ArchiveFileTypes = new[]
        {
            "*.zip",
            "*.bz2",
            "*.bzip2",
            "*.gz",
            "*.gzip",
        };

        // hardcoded list of supported OpenXml document types
        // don't forget that file extension might be spoofed by attacker, so let's to try all possible filetypes (even old .xls or .doc)
        public static readonly IEnumerable<string> OpenXmlDocumentFileTypes = new[]
        {
            "*.xls",
            "*.xlsx",
            "*.doc",
            "*.docx",
            "*.ppt",
            "*.pptx",
            "*.pps",
            "*.ppsx",
            "*.sldx",
        };
    }
}
