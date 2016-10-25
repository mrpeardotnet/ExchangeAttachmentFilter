namespace MrPear.Net.ExchangeAttachmentFilter
{
    public enum AttachmentFilterStatusEnum
    {
        Accept = 0,
        RemoveAttachment = 1,
        StripAttachment = 2,
        RejectMessage = 3,
    }

    public class AttachmentFilterStatus
    {
        public AttachmentFilterStatus(AttachmentFilterStatusEnum status, string reason)
        {
            Status = status;
            Reason = reason;
        }

        public AttachmentFilterStatusEnum Status { get; }
        public string Reason { get; }
    }
}
