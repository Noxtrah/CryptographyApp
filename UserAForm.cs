namespace CryptographyApp;

#nullable enable

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
    public partial class UserAForm : Form
    {
        private Button fileSelectButton = null!;
        private Button signFileButton = null!;
        private Button encryptFileButton = null!;
        private Button signAndEncryptFileButton = null!;
        private Button sendButton = null!;
        private Button openUserBButton = null!;
        private Label selectedFileLabel = null!;
        private Label errorMessageLabel = null!;
        private TextBox fileContentTextBox = null!;
        private string selectedFilePath = string.Empty;
        private bool isOperationPerformed = false;
        private bool signContent = false;
        private bool encryptContent = false;
        private string processedContent = string.Empty;
        private readonly string key = KeyManager.SymmetricKey;
        private static readonly RSAParameters senderPrivateKey = KeyManager.AsymmetricPrivateKey;
        public static readonly RSAParameters senderPublicKey = KeyManager.AsymmetricPublicKey;
        public static readonly RSAParameters recipientPublicKey = KeyManager.AsymmetricPrivateKey;
        private string plainText = null!;
        string encryptedSessionKey = null!;
        public List<Messages> messages = new List<Messages>();

        public UserAForm()
        {
            InitializeButton();
            InitializeLabel();
            InitializeTextBox();
            InitializeErrorMessageLabel();

            Text = "User A Form";
            Size = new System.Drawing.Size(800, 450);

            Controls.Add(fileSelectButton);
            Controls.Add(selectedFileLabel);
            Controls.Add(fileContentTextBox);
            Controls.Add(signFileButton);
            Controls.Add(encryptFileButton);
            Controls.Add(signAndEncryptFileButton);
            Controls.Add(sendButton);
            Controls.Add(openUserBButton);
            Controls.Add(errorMessageLabel);
        }

        private void InitializeButton()
        {
            fileSelectButton = new Button
            {
                Text = "Select File",
                Location = new System.Drawing.Point(10, 30)
            };
            fileSelectButton.Click += FileSelectButton_Click;

            signFileButton = new Button
            {
                Text = "Sign File",
                Location = new System.Drawing.Point(10, 300)
            };

            signFileButton.Click += SignFileButton_Click;

            encryptFileButton = new Button
            {
                Text = "Encrypt File",
                Location = new System.Drawing.Point(100, 300),
                Size = new System.Drawing.Size(90, 23)
            };

            encryptFileButton.Click += EncryptFileButton_Click;

            signAndEncryptFileButton = new Button
            {
                Text = "Sign and Encrypt File",
                Location = new System.Drawing.Point(205, 300),
                Size = new System.Drawing.Size(180, 23)
            };

            signAndEncryptFileButton.Click += SignAndEncryptFileButton_Click;

            sendButton = new Button
            {
                Text = "Send File",
                Location = new System.Drawing.Point(400, 300),
                Size = new System.Drawing.Size(90, 23)
            };

            sendButton.Click += SendButton_Click;

            openUserBButton = new Button
            {
                Text = "Open UserBForm",
                Location = new System.Drawing.Point(510, 300),
                Size = new System.Drawing.Size(150, 23)
            };
            openUserBButton.Click += OpenUserBButton_Click;
        }

        private void InitializeLabel()
        {
            selectedFileLabel = new Label
            {
                Text = "Selected File: ",
                Location = new System.Drawing.Point(150, 35),
                AutoSize = true 
            };
        }

        private string GetSelectedFilePath()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                selectedFileLabel.Text = $"Selected File: {System.IO.Path.GetFileName(openFileDialog.FileName)}";
                return openFileDialog.FileName;
            }

            return string.Empty;
        }

        private void FileSelectButton_Click(object? sender, EventArgs e)
        {
            ResetState();
            selectedFilePath = GetSelectedFilePath();

            if (!string.IsNullOrEmpty(selectedFilePath))
            {
                try
                {
                    string fileContent = File.ReadAllText(selectedFilePath);
                    plainText = fileContent;
                    fileContentTextBox.Text = fileContent;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error reading file: {ex.Message}", "Error");
                }
            }
        }

        private void EncryptFileButton_Click(object? sender, EventArgs e)
        {
            if (isOperationPerformed)
            {
                DisplayMessage("Cannot perform another operation on the file.");
                return;
            }

            if(fileContentTextBox.Text != "")
            {
                
                isOperationPerformed = true;
                signContent = false;
                encryptContent = true;
                // Encrypts the content of textBox
                processedContent = AesOperation.EncryptString(key,fileContentTextBox.Text);
                CloseButtons();
                DisplayProcessedContent();
                DisplayMessage("File is successfully encrypted!");
            }
        }

        private void SignFileButton_Click(object? sender, EventArgs e)
        {
            if (isOperationPerformed)
            {
                DisplayMessage("Cannot perform another operation on the file.");
                return;
            }

            if(fileContentTextBox.Text != "")
            {
                isOperationPerformed = true;
                signContent = true;
                encryptContent = false;
                // Signs the content of textBox
                processedContent = SignatureOperations.SignText(senderPrivateKey, fileContentTextBox.Text);
                CloseButtons();
                DisplayProcessedContent();
                DisplayMessage("File is successfully signed!");
            }
        }

        private void SignAndEncryptFileButton_Click(object? sender, EventArgs e)
        {
             if (isOperationPerformed)
            {
                DisplayMessage("Cannot perform another operation on the file.");
                return;
            }

            if(fileContentTextBox.Text != "")
            {
                isOperationPerformed = true;
                signContent = true;
                encryptContent = true;
                string originalHash = SignatureOperations.CalculateHash(fileContentTextBox.Text);

                // Sign the hash using the sender's private key
                string digitalSignature = SignatureOperations.SignText(senderPrivateKey, originalHash);

                // Generate one-time session key
                string sessionKey = KeyGenerator.GetRandomStringKey();

                // Encrypt the message body with the session key
                string encryptedMessageBody = AesOperation.EncryptString(sessionKey, fileContentTextBox.Text);

                // Encrypt the session key with UserB's public key
                encryptedSessionKey = KeyManager.EncryptSessionKey(recipientPublicKey, sessionKey);

                // Combine the encrypted session key and encrypted message body
                processedContent = $"{digitalSignature}:{encryptedMessageBody}";

                CloseButtons();
                DisplayProcessedContent();
                DisplayMessage("File is successfully signed and encrypted!");
            }
        }

        private void DisplayProcessedContent()
        {
            fileContentTextBox.Text = processedContent;
        }

        private void SendButton_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(processedContent))
            {
                MessageBox.Show("Please process a file first.", "Error");
                return;
            }

            // Store the required variables for UserBForm in the list
            messages.Add(new Messages(plainText, processedContent, signContent, encryptContent, encryptedSessionKey, senderPublicKey));
            selectedFilePath = string.Empty;
            fileContentTextBox.Text = string.Empty;

            DisplayMessage("Message has successfully sent. You can either open 'User B Form' or send some more messages.");
            ResetState();
        }

        private void OpenUserBButton_Click(object? sender, EventArgs e)
        {
            UserBForm userBForm = new UserBForm(messages);
            userBForm.Show();
        }

        private void InitializeTextBox()
        {
            fileContentTextBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = true,
                ReadOnly = true,
                Size = new System.Drawing.Size(770, 200),
                Location = new System.Drawing.Point(10, 70) 
            };
        }

        private void InitializeErrorMessageLabel()
        {
            errorMessageLabel = new Label
            {
                Text = string.Empty,
                ForeColor = System.Drawing.Color.Green,
                Location = new System.Drawing.Point(10, 350), 
                AutoSize = true 
            };
        }

        private void DisplayMessage(string errorMessage)
        {
            errorMessageLabel.Text = errorMessage;
        }

        private void CloseButtons(){
            encryptFileButton.Enabled = false;
            signAndEncryptFileButton.Enabled = false;
            signFileButton.Enabled = false;
        }

        private void ResetState()
        {
            selectedFileLabel.Text = "Selected File: ";
            isOperationPerformed = false;
            encryptFileButton.Enabled = true;
            signAndEncryptFileButton.Enabled = true;
            signFileButton.Enabled = true;
            plainText = "";
            processedContent = "";
            selectedFilePath = "";
            fileContentTextBox.Text = "";
        }

    }