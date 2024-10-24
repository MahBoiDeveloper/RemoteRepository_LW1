using System;
using System.Linq;
using System.Numerics;
using System.Collections.Generic;

using InformationSecurity;
using System.Text;
class Program
{
    static void Main(string[] args)
    {
        //RSATest();
        //StreebogTest();
        KuznechikTest();
    }
    static void StreebogTest()
    {
        Streebog sbg = new Streebog();
        string tmp = "Hello World!";
        byte[] message =
        {
            0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,
            0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,
            0x30,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,
            0x34,0x33,0x32,0x31,0x30,0x39,0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x30
        };

        Console.WriteLine("Hashing 256-bit");
        Console.WriteLine("Original msg: " + Convert.ToHexString(message));
        Console.WriteLine("Hash: " + sbg.GetHash(message));
        Console.WriteLine("Original msg: " + tmp);
        Console.WriteLine("Hash: " + sbg.GetHash(tmp));
        Console.WriteLine();
        Console.WriteLine("Hashing 512-bit");
        Console.WriteLine("Original msg: " + Convert.ToHexString(message));
        Console.WriteLine("Hash: " + sbg.GetHash512(message));
        Console.WriteLine("Original msg: " + tmp);
        Console.WriteLine("Hash: " + sbg.GetHash512(tmp));
    }
    static void RSATest()
    {
        RSA rsa = new RSA();
        string msg = "Hello world!";
        Console.WriteLine("Original message: " + msg);
        var cipher = rsa.Encrypt(msg);
        var msgfromcipher = rsa.Decrypt(cipher);
        Console.WriteLine("Deciphered message: " + msgfromcipher);
        Console.WriteLine("Cipher: " +  cipher);

        if (msg != msgfromcipher)
        {
            Console.WriteLine("Messages aren't equal!");
            rsa.DebugPrint();
        }
    }
    static void KuznechikTest()
    {
        byte[] key1 = Convert.FromHexString("8899aabbccddeeff0011223344556677");
        byte[] key2 = Convert.FromHexString("fedcba98765432100123456789abcdef");
        byte[] msg  = Convert.FromHexString("1122334455667700ffeeddccbbaa9988");
        byte[] cip;
        Kuznechik kzn = new Kuznechik(key1, key2);
        Console.WriteLine("Original: " + Convert.ToHexString(msg));
        Console.WriteLine("Cipher:   " + Convert.ToHexString(cip = kzn.Encrypt(msg)));
        Console.WriteLine("Decipher: " + Convert.ToHexString(kzn.Decrypt(cip)));
    }
}
