using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace testni
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            test();

            return;

            Console.WriteLine("Server start call!");
            StartServer();

            Thread.Sleep(1500);
            Console.WriteLine("Klijent start call!");
            StartKlijent("pa kako je, ša ima?");

            Console.ReadKey();
        }

        private static void test()
        {
            var msg = "Ivona je mala!";
            var msg_array = Encoding.ASCII.GetBytes(msg);
            var key = makeKey();
            var iv = makeIV();
            var cry = Encrypt3DES_CBC(msg_array, key, iv, true);
            var decrx = Encrypt3DES_CBC(cry, key, iv, false);
            var izlaz = Encoding.ASCII.GetString(decrx);

            StreamReader txtStream = File.OpenText(@"ServerCert\server_rsa.pem");
            PemReader reader = new PemReader(txtStream);
            var obj = reader.ReadPemObject();
            var tst = obj.Generate();
            var t2 = Convert.ToBase64String((obj.Content));

            var num = new BigInteger("789");
            var publicKey = new MPInteger(num);

            var pubStringKey = publicKey.Value.ToString();
            int pubLength = pubStringKey.Length;

            var size = BitConverter.GetBytes(pubLength);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(size);

            List<byte> rezultat = new List<byte>();

            rezultat.AddRange(size);
            rezultat.AddRange(Encoding.ASCII.GetBytes(pubStringKey));

            var all = rezultat.ToArray();

            byte[] velicina = new byte[4];
            all.Take(size.Length);
            Array.Reverse(velicina);
            int packetSize = BitConverter.ToInt32(velicina, 0);

            var broj = all.Skip(4).ToArray();
            var brojString = Encoding.ASCII.GetString(broj);
            var bigintBroj = new BigInteger(brojString);

            bool valja = bigintBroj.Equals(num);
        }

        private static byte[] makeKey()
        {
            var KH_array = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x32 };
            var K_array = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03 };
            var H_array = new byte[] { 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x32 };

            var D = Convert.ToByte('D');
            var sessionIdent_array = Encoding.ASCII.GetBytes("SSH-2.0-klijent-v1.0");

            var forHash = new List<byte>();

            forHash.AddRange(KH_array);

            forHash.Add(D);

            forHash.AddRange(sessionIdent_array);

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var key_list = sha1.ComputeHash(forHash.ToArray()).ToList();
                /*
                If the key length needed is longer than the output of the HASH, the
                key is extended by computing HASH of the concatenation of K and H and
                the entire key so far, and appending the resulting bytes (as many as
                HASH generates) to the key
                 */
                while (key_list.Count < 24)
                {
                    var temp = new List<byte>();
                    temp.AddRange(K_array);
                    temp.AddRange(H_array);
                    temp.AddRange(key_list);
                    key_list.AddRange(sha1.ComputeHash(temp.ToArray()));
                }

                return key_list.Take(24).ToArray();
            }
        }

        private static byte[] makeIV()
        {
            var KH_array = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x32 };
            var K_array = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03 };
            var H_array = new byte[] { 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x32 };

            var A = Convert.ToByte('A');
            var sessionIdent_array = Encoding.ASCII.GetBytes("SSH-2.0-klijent-v1.0");

            var forHash = new List<byte>();

            forHash.AddRange(KH_array);

            forHash.Add(A);

            forHash.AddRange(sessionIdent_array);

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var key_list = sha1.ComputeHash(forHash.ToArray()).ToList();
                /*
                If the key length needed is longer than the output of the HASH, the
                key is extended by computing HASH of the concatenation of K and H and
                the entire key so far, and appending the resulting bytes (as many as
                HASH generates) to the key
                 */
                while (key_list.Count < 8)
                {
                    var temp = new List<byte>();
                    temp.AddRange(K_array);
                    temp.AddRange(H_array);
                    temp.AddRange(key_list);
                    key_list.AddRange(sha1.ComputeHash(temp.ToArray()));
                }

                return key_list.Take(8).ToArray();
            }
        }

        private static void StartKlijent(string msg)
        {
            var klijent = new klijent();
            klijent.Start(msg);
        }

        private static void StartServer()
        {
            Task.Run(() =>
            {
                server.Start();
            });
        }

        public static byte[] Encrypt3DES_CBC(byte[] message, byte[] key, byte[] iv, bool isEncryption)
        {
            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(desedeEngine), new Pkcs7Padding());
            // 192 bita ključ = 24 bajta
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            ParametersWithIV keyWithIV = new ParametersWithIV(keyparam, iv);

            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(isEncryption, keyWithIV);
            output = bufferedCipher.DoFinal(message);
            return output;
        }
    }

    public class klijent
    {
        public static void Start(string message)
        {
            Console.WriteLine("Klijent starting...");

            var client = new NamedPipeClientStream("SSHpipa");
            client.Connect();
            StreamReader reader = new StreamReader(client);
            StreamWriter writer = new StreamWriter(client);

            writer.WriteLine(message);
            writer.Flush();

            while (true)
            {
                string line = reader.ReadLine();

                int broj = int.Parse(line);

                Console.WriteLine("klijent izlaz - " + broj + " - ");

                broj++;

                writer.WriteLine(broj);
                writer.Flush();
            }
        }
    }

    public static class server
    {
        public static void Start()
        {
            Console.WriteLine("Server starting...");

            var server = new NamedPipeServerStream("SSHpipa", PipeDirection.InOut);
            server.WaitForConnection();
            StreamReader reader = new StreamReader(server);
            StreamWriter writer = new StreamWriter(server);
            string line = reader.ReadLine();
            Console.WriteLine("\n\n - " + line + " - \n\n");
            writer.WriteLine(0);
            writer.Flush();

            while (true)
            {
                line = reader.ReadLine();

                int broj = int.Parse(line);

                Console.WriteLine("server izlaz - " + broj + " - ");

                broj++;

                writer.WriteLine(broj);
                writer.Flush();

                Thread.Sleep(500);
            }
        }
    }
}