﻿using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;

using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace testni
{
    public static class ecdh_sha2_nistp521
    {
        public static AsymmetricCipherKeyPair getKeyPair()
        {
            X9ECParameters ecP = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            ECKeyPairGenerator g = new ECKeyPairGenerator();
            g.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));

            return g.GenerateKeyPair();
        }
    }

    internal class Program
    {
        private const string Algorithm = "ECDH"; //What do you think about the other algorithms?
        private const int KeyBitSize = 256;
        private const int NonceBitSize = 128;
        private const int MacBitSize = 128;
        private const int DefaultPrimeProbability = 30;

        private static void Main(string[] args)
        {
            string hexPublic = "45435333300000007617E192615E8C24D353E8BD11DE21E9C54DC2D9D64C21AEC35A372B0EB3C205597BA20C0944FA6AFE871D23076F1D9711B5AAE0817BEAA6B953E9DF186B6BE1048050759005396B0A2856CF464C2E927916B0958CACEF8132A79C62456C8421";
            string hexPrivate = "45435334300000007617E192615E8C24D353E8BD11DE21E9C54DC2D9D64C21AEC35A372B0EB3C205597BA20C0944FA6AFE871D23076F1D9711B5AAE0817BEAA6B953E9DF186B6BE1048050759005396B0A2856CF464C2E927916B0958CACEF8132A79C62456C842115772EBB4C4A3078DE768FCE8A8156380A6047E160BCFCAD24FB70416CFCCE0E693961D7C0F1198BA8B25CC2A6EF4C6D";

            hexPublic = File.ReadAllLines(@"ServerCert\ECDSA.public")[0];
            hexPrivate = File.ReadAllLines(@"ServerCert\ECDSAPrivate.key")[0];

            string msg0 = "poruka";
            byte[] data = Encoding.ASCII.GetBytes(msg0);

            var bytesKey = Enumerable.Range(0, hexPrivate.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hexPrivate.Substring(x, 2), 16)).ToArray();

            CngKey key = CngKey.Import(bytesKey, CngKeyBlobFormat.EccPrivateBlob);
            /*
            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP384, null, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport });

            var pubK = key.Export(CngKeyBlobFormat.EccPublicBlob);
            var privK = key.Export(CngKeyBlobFormat.EccPrivateBlob);

            var hexpub = BitConverter.ToString(pubK).Replace("-", "");
            var hexpriv = BitConverter.ToString(privK).Replace("-", "");
            */
            ECDsaCng dsa = new ECDsaCng(key);

            String xmlExport = dsa.ToXmlString(ECKeyXmlFormat.Rfc4050);

            byte[] signature = dsa.SignData(data);

            /******************************/

            var bytesKey2 = Enumerable.Range(0, hexPublic.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hexPublic.Substring(x, 2), 16)).ToArray();

            CngKey key2 = CngKey.Import(bytesKey2, CngKeyBlobFormat.EccPublicBlob);

            ECDsaCng eccImporter = new ECDsaCng(key2);

            //eccImporter.FromXmlString(xmlExport, ECKeyXmlFormat.Rfc4050);

            if (eccImporter.VerifyData(data, signature))
            {
                Console.WriteLine("Verified using .NET");
            }

            #region early testing

            /*

            string msg = "The quick brown fox jumps over the lazy dog";
            string msg2 = "1vo je test";
            var a = Encoding.ASCII.GetBytes(msg);
            var b = Encoding.ASCII.GetBytes(msg2);
            var keey = makeGostKey();

            var e1 = Compute_gost28147(a, keey);
            var e2 = Compute_gost28147(b, keey);

            AsymmetricCipherKeyPair keyPair = ecdh_sha2_nistp521.getKeyPair();
            var o = keyPair.Public as ECPublicKeyParameters;
            var ui = o.PublicKeyParamSet;
            var senderPrivate = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArrayUnsigned();
            var senderPublic = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded();

            var p = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(senderPrivate);
            var pub = ((ECPublicKeyParameters)keyPair.Public).Q.ToString();
            var pub2 = BitConverter.ToString(senderPublic).Replace("-", "").ToLower();

            var par = GenerateParameters();
            Debug.WriteLine(par.P.ToString());
            Debug.WriteLine(par.G.ToString());

            TestBouncy(par);
            //TestMethod();

            Console.WriteLine("Server start call!");
            StartServer();

            Thread.Sleep(1500);
            Console.WriteLine("Klijent start call!");
            StartKlijent("pa kako je, ša ima?");

            */

            #endregion early testing

            Console.ReadKey();
        }

        /// <summary>
        /// IMPLEMENTACIJA JE TAKVA DA VRATI 4 bajta
        /// </summary>
        /// <param name="paket"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Compute_gost28147(byte[] paket, byte[] key)
        {
            Gost28147Mac gost = new Gost28147Mac();
            KeyParameter param = new KeyParameter(key, 0, key.Length);
            gost.Init(param);

            gost.BlockUpdate(key, 0, key.Length);

            var macS = gost.GetMacSize();

            byte[] output = new byte[macS];
            int b = gost.DoFinal(output, 0);

            return output;
        }

        private static byte[] makeGostKey()
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
                while (key_list.Count < 32)
                {
                    var temp = new List<byte>();
                    temp.AddRange(K_array);
                    temp.AddRange(H_array);
                    temp.AddRange(key_list);
                    key_list.AddRange(sha1.ComputeHash(temp.ToArray()));
                }

                return key_list.Take(32).ToArray();
            }
        }

        public static DHParameters GenerateParameters()
        {
            var generator = new DHParametersGenerator();
            generator.Init(256, DefaultPrimeProbability, new SecureRandom());
            return generator.GenerateParameters();
        }

        public static void TestBouncy(DHParameters par)
        {
            X9ECParameters ecP = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            ECKeyPairGenerator g = new ECKeyPairGenerator();
            g.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));

            //
            // a side
            //
            AsymmetricCipherKeyPair aKeyPair = g.GenerateKeyPair();
            IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
            aKeyAgree.Init(aKeyPair.Private);
            ECPublicKeyParameters pubKey1 = (ECPublicKeyParameters)aKeyPair.Public;

            BigInteger asx1 = pubKey1.Q.X.ToBigInteger();
            byte[] axb = asx1.ToByteArray();

            BigInteger asy1 = pubKey1.Q.Y.ToBigInteger();
            byte[] ayb = asy1.ToByteArray();

            // client public key X co-ordinate Hex string
            StringBuilder axhex = new StringBuilder(axb.Length * 2);
            foreach (byte b in axb)
                axhex.AppendFormat("{0:x2}", b);
            string xHex = axhex.ToString();

            // client public key Y co-ordinate Hex string
            StringBuilder ayhex = new StringBuilder(ayb.Length * 2);
            foreach (byte b in ayb)
                ayhex.AppendFormat("{0:x2}", b);
            string yHex = ayhex.ToString();

            Console.WriteLine(string.Format("Alice X coordinate {0}", xHex));
            Console.WriteLine(string.Format("Alice Y coordinate {0}", yHex));

            //
            // b side
            //
            AsymmetricCipherKeyPair bKeyPair = g.GenerateKeyPair();
            IBasicAgreement bKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
            aKeyAgree.Init(bKeyPair.Private);
            ECPublicKeyParameters pubKey2 = (ECPublicKeyParameters)aKeyPair.Public;

            BigInteger bsx1 = pubKey2.Q.X.ToBigInteger();
            byte[] bxb = bsx1.ToByteArray();

            BigInteger bsy1 = pubKey2.Q.Y.ToBigInteger();
            byte[] byb = bsy1.ToByteArray();

            // client public key X co-ordinate Hex string
            StringBuilder bxhex = new StringBuilder(bxb.Length * 2);
            foreach (byte b in bxb)
                bxhex.AppendFormat("{0:x2}", b);
            string xbHex = bxhex.ToString();

            // client public key Y co-ordinate Hex string
            StringBuilder byhex = new StringBuilder(byb.Length * 2);
            foreach (byte b in byb)
                byhex.AppendFormat("{0:x2}", b);
            string ybHex = byhex.ToString();

            Console.WriteLine(string.Format("Bob X coordinate {0}", xbHex));
            Console.WriteLine(string.Format("Bob Y coordinate {0}", ybHex));

            string BobXhex = xbHex;

            string BobYhex = ybHex;

            FpCurve c = (FpCurve)ecSpec.Curve;

            ECFieldElement x = new FpFieldElement(c.Q, new BigInteger(BobXhex, 16));
            ECFieldElement y = new FpFieldElement(c.Q, new BigInteger(BobYhex, 16));
            ECPoint q = new FpPoint(ecP.Curve, x, y);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters("ECDH", q, SecObjectIdentifiers.SecP521r1);

            BigInteger k1 = aKeyAgree.CalculateAgreement(publicKey);
            byte[] genKey = k1.ToByteArray();

            StringBuilder genKeySB = new StringBuilder(genKey.Length * 2);
            foreach (byte b in genKey)
                genKeySB.AppendFormat("{0:x2}", b);
            string genratedKey = genKeySB.ToString();
            Console.WriteLine(string.Format("Generated Key {0}", genratedKey));

            //calc sha-256 now
            IDigest hash = new Sha256Digest();
            byte[] result = new byte[hash.GetDigestSize()];
            hash.BlockUpdate(genKey, 0, genKey.Length);
            hash.DoFinal(result, 0);

            StringBuilder share = new StringBuilder(result.Length * 2);
            foreach (byte b in result)
                share.AppendFormat("{0:x2}", b);
            string sharedKey = share.ToString();
            Console.WriteLine(string.Format("Shared Key {0}", sharedKey));

            Console.ReadLine();
        }

        private static byte[] GetBytes(string str)
        {
            if (str == null) return null;
            return Encoding.ASCII.GetBytes(str);
        }

        private static string GetString(byte[] bytes)
        {
            if (bytes == null) return null;
            return Encoding.ASCII.GetString(bytes, 0, bytes.Length);
        }

        private static string DecryptMessage(string sharedKey, byte[] encryptedMessage, out string nonSecretPayload)
        {
            byte[] nonSecretPayloadBytes;
            byte[] payload = DecryptMessage(new KeyParameter(Convert.FromBase64String(sharedKey)), encryptedMessage, out nonSecretPayloadBytes);

            nonSecretPayload = GetString(nonSecretPayloadBytes);
            return GetString(payload);
        }

        private static byte[] DecryptMessage(KeyParameter sharedKey, byte[] encryptedMessage, out byte[] nonSecretPayloadBytes)
        {
            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Payload
                int nonSecretLength = (int)cipherReader.ReadByte();
                nonSecretPayloadBytes = cipherReader.ReadBytes(nonSecretLength);

                //Grab Nonce
                var nonce = cipherReader.ReadBytes(NonceBitSize / 8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                var parameters = new AeadParameters(sharedKey, MacBitSize, nonce, nonSecretPayloadBytes);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonSecretLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    //Return null if it doesn't authenticate
                    return null;
                }

                return plainText;
            }
        }

        private static byte[] EncryptMessage(KeyParameter sharedKey, byte[] nonSecretMessage, byte[] secretMessage)
        {
            if (nonSecretMessage != null && nonSecretMessage.Length > 255) throw new Exception("Non Secret Message Too Long!");
            byte nonSecretLength = nonSecretMessage == null ? (byte)0 : (byte)nonSecretMessage.Length;

            var nonce = new byte[NonceBitSize / 8];
            var rand = new SecureRandom();
            rand.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            var aeadParameters = new AeadParameters(sharedKey, MacBitSize, nonce, nonSecretMessage);
            cipher.Init(true, aeadParameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
            var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(nonSecretLength);
                    binaryWriter.Write(nonSecretMessage);

                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        private static byte[] EncryptMessage(string sharedKey, string nonSecretMessage, string secretMessage)
        {
            return EncryptMessage(new KeyParameter(Convert.FromBase64String(sharedKey)), GetBytes(nonSecretMessage), GetBytes(secretMessage));
        }

        public static void TestMethod()
        {
            //BEGIN SETUP ALICE
            IAsymmetricCipherKeyPairGenerator aliceKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
            DHParametersGenerator aliceGenerator = new DHParametersGenerator();
            aliceGenerator.Init(KeyBitSize, DefaultPrimeProbability, new SecureRandom());
            DHParameters aliceParameters = aliceGenerator.GenerateParameters();

            KeyGenerationParameters aliceKGP = new DHKeyGenerationParameters(new SecureRandom(), aliceParameters);
            aliceKeyGen.Init(aliceKGP);

            AsymmetricCipherKeyPair aliceKeyPair = aliceKeyGen.GenerateKeyPair();
            IBasicAgreement aliceKeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
            aliceKeyAgree.Init(aliceKeyPair.Private);

            //END SETUP ALICE

            /////AT THIS POINT, Alice's Public Key, Alice's Parameter P and Alice's Parameter G are sent unsecure to BOB

            //BEGIN SETUP BOB
            IAsymmetricCipherKeyPairGenerator bobKeyGen = GeneratorUtilities.GetKeyPairGenerator(Algorithm);
            DHParameters bobParameters = new DHParameters(aliceParameters.P, aliceParameters.G);

            KeyGenerationParameters bobKGP = new DHKeyGenerationParameters(new SecureRandom(), bobParameters);
            bobKeyGen.Init(bobKGP);

            AsymmetricCipherKeyPair bobKeyPair = bobKeyGen.GenerateKeyPair();
            IBasicAgreement bobKeyAgree = AgreementUtilities.GetBasicAgreement(Algorithm);
            bobKeyAgree.Init(bobKeyPair.Private);
            //END SETUP BOB

            BigInteger aliceAgree = aliceKeyAgree.CalculateAgreement(bobKeyPair.Public);
            BigInteger bobAgree = bobKeyAgree.CalculateAgreement(aliceKeyPair.Public);

            if (!aliceAgree.Equals(bobAgree))
            {
                throw new Exception("Keys do not match.");
            }

            byte[] nonSecretMessage = GetBytes("HeaderMessageForASDF");
            byte[] secretMessage = GetBytes("Secret message contents");
            byte[] decNonSecretBytes;

            KeyParameter sharedKey = new KeyParameter(aliceAgree.ToByteArrayUnsigned());

            var encMessage = EncryptMessage(sharedKey, nonSecretMessage, secretMessage);
            var decMessage = DecryptMessage(sharedKey, encMessage, out decNonSecretBytes);

            var decNonSecretMessage = GetString(decNonSecretBytes);
            var decSecretMessage = GetString(decMessage);

            Debug.WriteLine(decNonSecretMessage + " - " + decSecretMessage);
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