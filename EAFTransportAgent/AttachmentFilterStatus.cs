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
        public AttachmentFilterStatus(AttachmentFilterStatusEnum status, int statusTag, string reason)
        {
            Status = status;
            StatusTag = statusTag;
            Reason = reason;
        }

        public AttachmentFilterStatus(AttachmentFilterStatusEnum status, string reason)
            :this(status, 0, reason)
        { }

        public AttachmentFilterStatusEnum Status { get; }
        public string Reason { get; }
        public int StatusTag { get; }
    }
}
