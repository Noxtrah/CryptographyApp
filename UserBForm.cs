#nullable enable

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

public partial class UserBForm : Form
{
    private RichTextBox fileContentTextBox = null!;
    private ComboBox messageComboBox = null!;
    private Label messageLabel = null!;
    private Label displayMessageLabel = null!;
    private string processedContent = null!;
    private bool isSigned;
    private bool isEncrypted;
    private readonly string key = KeyManager.SymmetricKey;
    public RSAParameters senderPublicKey;
    private static readonly RSAParameters asymmetricPrivateKey = KeyManager.AsymmetricPrivateKey;
    private string plainText = null!;
    private string encryptedSessionKey = null!;
    private List<Messages> messages;
    public UserBForm(List<Messages> messages)
    {
        

        Text = "User B Form";
        Size = new System.Drawing.Size(800, 450);

        this.messages = messages ?? throw new ArgumentNullException(nameof(messages));

        InitializeComponent();

        if (this.messages.Count > 0)
        {
            var firstMessage = this.messages[0];
            // Set values based on the first message
            processedContent = firstMessage.ProcessedContent;
            isSigned = firstMessage.IsSigned;
            isEncrypted = firstMessage.IsEncrypted;
            plainText = firstMessage.PlainText;
            encryptedSessionKey = firstMessage.EncryptedSessionKey;
            senderPublicKey = firstMessage.SenderPublicKey;

            DisplayContent(isSigned, isEncrypted);
        }
        DisplayContent(isSigned, isEncrypted);
    }

    private void DisplayContent(bool isSigned, bool isEncrypted)
{
    try
    {
        if (isEncrypted && isSigned)
        {
            // Decrypt the session key using UserB's private key
            string decryptedSessionKey = KeyManager.DecryptSessionKey(asymmetricPrivateKey, encryptedSessionKey);

            // Split the processed content
            string[] contentParts = processedContent.Split(':');
            string digitalSignature = contentParts[0];
            string encryptedMessageBody = contentParts[1];

            // Calculate the hash of the decrypted message body
            string decryptedHash = SignatureOperations.CalculateHash(AesOperation.DecryptString(decryptedSessionKey, encryptedMessageBody));

            // Verify the signature using UserA's public key
            bool isSignatureValid = SignatureOperations.VerifySign(senderPublicKey, decryptedHash, digitalSignature);

            if (isSignatureValid)
            {
                // Decrypt the message body with the decrypted session key
                string decryptedMessageBody = AesOperation.DecryptString(decryptedSessionKey, encryptedMessageBody);

                // Display the decrypted message body
                fileContentTextBox.Text = decryptedMessageBody;
                fileContentTextBox.SelectionStart = fileContentTextBox.Text.Length;
                fileContentTextBox.SelectionLength = 0;
                fileContentTextBox.SelectionFont = new Font(fileContentTextBox.Font, FontStyle.Italic);
                fileContentTextBox.AppendText(" (Signature Verified).");
                fileContentTextBox.SelectionFont = new Font(fileContentTextBox.Font, FontStyle.Regular); // Reset the font style
            }
            else
            {
                fileContentTextBox.Text = "Invalid Signature";
                 
            }
        }
        else if(isEncrypted)
        {
            string decryptedContent = AesOperation.DecryptString(key,processedContent);
            fileContentTextBox.Text = decryptedContent;           
        }
        else if(isSigned)
        {
            bool isVerified = SignatureOperations.VerifySign(senderPublicKey, plainText, processedContent);
            fileContentTextBox.Text = isVerified ? "Signature Verified" : "Invalid Signature";
        }
    }
    catch (Exception ex)
    {
        fileContentTextBox.Text = $"Error displaying content: {ex.Message}";
    }
}

    private void InitializeComponent()
    {
        displayMessageLabel = new Label
        {
            Text = "Displayed message:",
            ForeColor = System.Drawing.Color.Black,
            Location = new System.Drawing.Point(10, 50), 
            AutoSize = true 
        };

        fileContentTextBox = new RichTextBox
        {
            Multiline = true,
            ScrollBars = RichTextBoxScrollBars.Both,
            WordWrap = false,
            ReadOnly = true,
            Size = new System.Drawing.Size(770, 200),
            Location = new System.Drawing.Point(10, 70)
        };

        messageLabel = new Label
        {
            Text = "Please select the file to display from below!",
            ForeColor = System.Drawing.Color.Black,
            Location = new System.Drawing.Point(10, 310), 
            AutoSize = true 
        };

        messageComboBox = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new System.Drawing.Point(10, 330),
            Width = 300
        };

        messageComboBox.SelectedIndexChanged += MessageComboBox_SelectedIndexChanged;

        // Add messages to the ComboBox
        if (messages != null && messages.Count != 0)
        {
            foreach (var message in messages)
            {
                if (!string.IsNullOrEmpty(message.PlainText))
                {
                    messageComboBox.Items.Add(message.PlainText);
                }
            }
            messageComboBox.SelectedIndex = 0;
        }

        Controls.Add(displayMessageLabel);
        Controls.Add(fileContentTextBox);
        Controls.Add(messageLabel);
        Controls.Add(messageComboBox);
    }

    private void MessageComboBox_SelectedIndexChanged(object sender, EventArgs e)
    {
        // Display the selected message when the user changes the selection in the ComboBox
        Console.WriteLine("SelectedIndexChanged event triggered.");
        int selectedIndex = messageComboBox.SelectedIndex;
        DisplaySelectedMessage(selectedIndex);
    }

   private void DisplaySelectedMessage(int selectedIndex)
    {
        if (selectedIndex >= 0 && selectedIndex < messages.Count)
        {
            Messages selectedMessage = messages[selectedIndex];
            if (selectedMessage != null)
            {
                // Set values based on the selected message
                processedContent = selectedMessage.ProcessedContent;
                isSigned = selectedMessage.IsSigned;
                isEncrypted = selectedMessage.IsEncrypted;
                plainText = selectedMessage.PlainText;
                encryptedSessionKey = selectedMessage.EncryptedSessionKey;
                senderPublicKey = selectedMessage.SenderPublicKey;

                DisplayContent(isSigned, isEncrypted);
            }
            else
            {
                // Handle the case where selectedMessage is null
                fileContentTextBox.Text = "Selected message is null.";
            }
        }
        else
        {
            // Handle the case where selectedIndex is out of bounds
            fileContentTextBox.Text = "Invalid message index.";
        }

    }
}