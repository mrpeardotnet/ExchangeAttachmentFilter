using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Routing;

namespace MrPear.Net.ExchangeAttachmentFilter
{
    /// <summary>
    /// Creates new instance of ExchangeAttachmentFilterFactory
    /// </summary>
    public class ExchangeAttachmentFilterFactory: RoutingAgentFactory
    {
        public override RoutingAgent CreateAgent(SmtpServer server)
        {
           return new ExchangeAttachmentFilterRoutingAgent(new ExchangeAttachmentFilterConfig());
        }
    }
}
