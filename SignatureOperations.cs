using System;
using System.Security.Cryptography;
using System.Text;

public class SignatureOperations
{
    public static string SignText(RSAParameters privateKey, string plainText)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);

                // Convert the plain text to bytes
                byte[] textBytes = Encoding.UTF8.GetBytes(plainText);

                // Compute the signature for the text
                byte[] signatureBytes = rsa.SignData(textBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Convert the signature to Base64 string
                return Convert.ToBase64String(signatureBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error signing text: {ex.Message}");
            return string.Empty;
        }
    }


    public static bool VerifySign(RSAParameters publicKey, string plainText, string signature)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);

                // Convert the plain text to bytes
                byte[] textBytes = Encoding.UTF8.GetBytes(plainText);

                // Convert the Base64-encoded signature to bytes
                byte[] signatureBytes = Convert.FromBase64String(signature);

                // Verify the signature for the text
                return rsa.VerifyData(textBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error verifying signature: {ex.Message}");
            return false;
        }
    }

    public static string CalculateHash(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hashBytes);
        }
    }

}
