using System;
using System.Text;
using System.Security.Cryptography;

namespace AesTest
{
    class Program
    {
        static void Main(string[] args)
        {
            // This was the output of our Python program.
            string enc_cipher = "ZeYXkFf8wPbvzdC91V4adwx4U56o2zMMOathdDYuBOE=";

            var textEncoder = new UTF8Encoding();

            // defaults to CBC and PKCS7
            var aes = new AesManaged();
            aes.Key = textEncoder.GetBytes("your key 16bytes");
            aes.IV = textEncoder.GetBytes("1234567812345678");

            var decryptor = aes.CreateDecryptor();
            var cipher = Convert.FromBase64String(enc_cipher);
            var text_bytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

            var text = textEncoder.GetString(text_bytes);
            // Should print 'This is my plain text'
            Console.WriteLine(text);
        }
    }
}