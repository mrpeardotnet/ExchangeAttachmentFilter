using System;
using System.Text;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    public class SysLogBuilder
    {
        private readonly StringBuilder _logStringBuilder = new StringBuilder();


        public void Log(string message)
        {
            _logStringBuilder.AppendLine(SysLog.FormatLogMessage(message, DateTime.Now));
            MessageCount++;
        }

        public void LogPadded(string message)
        {
            _logStringBuilder.AppendLine(SysLog.FormatLogMessage(message, DateTime.Now, 2));
            MessageCount++;
        }

        public override string ToString()
        {
            return _logStringBuilder.ToString();
        }

        public int MessageCount { get; private set; } = 0;
    }
}
