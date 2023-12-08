using System.Security.Cryptography;

public class KeyGenerator
{
    // Generate and get RSA key pair
    public static (RSAParameters PublicKey, RSAParameters PrivateKey) GetRsaKeyPair()
    {
        using (RSA rsa = RSA.Create())
        {
            return (
                PublicKey: rsa.ExportParameters(false),
                PrivateKey: rsa.ExportParameters(true)
            );
        }
    }

    // Generate and get symmetric key
    public static string GetSymmetricKey(int keySize)
    {
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = keySize;
            aes.GenerateKey();
            return Convert.ToBase64String(aes.Key);
        }
    }

    public static string GetRandomStringKey()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        char[] key = new char[32];

        Random random = new Random();

        for (int i = 0; i < key.Length; i++)
        {
            key[i] = chars[random.Next(chars.Length)];
        }

        return new string(key);
    }
}