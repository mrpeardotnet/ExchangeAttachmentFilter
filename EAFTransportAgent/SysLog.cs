using System;
using System.IO;
using System.Reflection;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    /// <summary>
    /// Logs information messages with timestamp to the text log file.
    /// Creates new log file every day.
    /// </summary>
    public static class SysLog
    {
        private static readonly object FileLock = new object();

        /// <summary>
        /// Logs text message to the current log file.
        /// </summary>
        /// <param name="message">Message to log.</param>
        public static void Log(string message)
        {
            lock (FileLock)
            {
                using (var logWriter = File.AppendText(GetLogFilePath()))
                {
                    var formattedMessage = FormatLogMessage(message, DateTime.Now);
                    logWriter.WriteLine(formattedMessage);
                    logWriter.Flush();
                }
            }
        }

        public static void Log(SysLogBuilder sysLogBuilder)
        {
            lock (FileLock)
            {
                using (var logWriter = File.AppendText(GetLogFilePath()))
                {
                    logWriter.Write(sysLogBuilder.ToString());
                    logWriter.Flush();
                }
            }
        }

        public static string FormatLogMessage(string message, DateTime dateTime, int padding = 0)
        {
            return $"[{dateTime.Hour:D2}:{dateTime.Minute:D2}:{dateTime.Second:D2}.{dateTime.Millisecond:D3}] {new string(' ', padding)}{message}";
        }

        private static string GetLogFilePath()
        {
            var logDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + $"\\{Config.ConfigDirectoryName}";
            var dateTimeNow = DateTime.Now;
            var logFileName = $"{dateTimeNow.Year:D4}-{dateTimeNow.Month:D2}-{dateTimeNow.Day:D2}.log";
            var logFile = Path.Combine(logDir, logFileName);
            if (!Directory.Exists(logDir))
                Directory.CreateDirectory(logDir);
            if (!File.Exists(logFile))
                File.CreateText(logFile).Close();
            return logFile;
        }
    }
}
