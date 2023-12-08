using System.Security.Cryptography;

public class Messages
{
    public Messages(string plainText, string processedContent, bool isSigned, bool isEncrypted, string encryptedSessionKey, RSAParameters senderPublicKey)
    {
        this.PlainText = plainText;
        this.ProcessedContent = processedContent;
        this.IsSigned = isSigned;
        this.IsEncrypted = isEncrypted;
        this.EncryptedSessionKey = encryptedSessionKey;
        this.SenderPublicKey = senderPublicKey;
    }
    public string PlainText { get; set; }
    public string ProcessedContent { get; set; }
    public bool IsSigned { get; set; }
    public bool IsEncrypted { get; set; }
    public string EncryptedSessionKey { get; set; }
    public RSAParameters SenderPublicKey { get; set; }
}