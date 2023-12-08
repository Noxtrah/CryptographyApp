using System.Security.Cryptography;
using System.Text;

public static class KeyManager
{
    private static readonly string symmetricKey = KeyGenerator.GetRandomStringKey();

    public static string SymmetricKey => symmetricKey;

    private static readonly (RSAParameters PublicKey, RSAParameters PrivateKey) rsaKeyPair = KeyGenerator.GetRsaKeyPair();

    public static RSAParameters AsymmetricPublicKey => rsaKeyPair.PublicKey;
    public static RSAParameters AsymmetricPrivateKey => rsaKeyPair.PrivateKey;

    public static string EncryptSessionKey(RSAParameters publicKey, string sessionKey)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);

                // Convert the session key to bytes
                byte[] sessionKeyBytes = Encoding.UTF8.GetBytes(sessionKey);

                // Encrypt the session key with UserB's public key
                byte[] encryptedSessionKeyBytes = rsa.Encrypt(sessionKeyBytes, RSAEncryptionPadding.Pkcs1);

                // Convert the encrypted session key to Base64 string
                return Convert.ToBase64String(encryptedSessionKeyBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error encrypting session key: {ex.Message}");
            return string.Empty;
        }
    }

    public static string DecryptSessionKey(RSAParameters privateKey, string encryptedText)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);

                // Convert the Base64-encoded encrypted text to bytes
                byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

                // Decrypt the bytes
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

                // Convert the decrypted bytes to a string
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                return decryptedText;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error decrypting with private key: {ex.Message}");
            return string.Empty;
        }
    }

    public static string DecryptWithPublicKey(RSAParameters publicKey, string encryptedText)
    {
        Console.WriteLine("Imported Modulus: " + BitConverter.ToString(publicKey.Modulus));
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                Console.WriteLine("Encrypted Text: " + encryptedText);
                Console.WriteLine("Imported Modulus: " + BitConverter.ToString(rsa.ExportParameters(false).Modulus));

                // Convert the Base64-encoded encrypted text to bytes
                byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                Console.WriteLine("Encrypted Bytes: " + BitConverter.ToString(encryptedBytes));
                // Decrypt the bytes
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

                // Convert the decrypted bytes to a string
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                return decryptedText;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error decrypting with public key: {ex.ToString()}");
            return string.Empty;
        }
    }
}
