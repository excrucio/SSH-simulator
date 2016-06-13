using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public static class SSHHelper
    {
        public static byte[] CreatePacket(byte[] informations)
        {
            // duljina paketa[4] (bez sebe i MAC-a) | duljina dopune[1] | korisne informacije[duljina paketa - duljina dopune -1] | dopuna[od 4 do mod 8, max 255] | MAC

            // ispuna od 4 ili više baytova do mod 8
            // +4 zbog broja koji označava duljinu paketa i +1 za broj koji označava duljinu dopune, a ovdje ih trenutno nema...
            int fillNum = (informations.Length + 4 + 1) % 8;

            fillNum = 8 - fillNum;

            if (fillNum < 4)
            {
                fillNum += 8;
            }

            byte[] filler = new byte[fillNum];

            for (int i = 0; i < fillNum; i++)
            {
                filler[i] = 0x0;
            }

            List<byte> paket = new List<byte>();
            // +fillNum jer treba uzeti i duljinu dopune na kraju i +1 jer je toliko oznaka duljine dopune
            var size = BitConverter.GetBytes(informations.Length + fillNum + 1);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(size);

            var fillSize = BitConverter.GetBytes(fillNum);

            paket.AddRange(size);
            paket.Add(fillSize[0]);
            paket.AddRange(informations);
            paket.AddRange(filler);

            // MAC još nije dogovoren pa ga nema...
            return paket.ToArray();
        }

        public static string ispis(byte[] data)
        {
            string hex = BitConverter.ToString(data).Replace("-", " ");
            string text = Encoding.ASCII.GetString(data).Replace('\0', '.').Replace('\n', '.').Replace('\r', '.').Replace('\v', '.').Replace('\t', '.').Replace('\f', '.');

            int i = 0;
            int j = 0;
            int len = hex.Length;
            int len2 = text.Length;

            string output = "";
            try
            {
                while (i < len - 47)
                {
                    output += hex.Substring(i, 47) + "      " + text.Substring(j, 16) + "\n";

                    i += 47 + 1;
                    j += 16;
                }

                int fill = 0;
                if (len2 - j < 16)
                {
                    fill = 47 - (len2 - j) * 3 + 1;
                }

                output += hex.Substring(i, len - i) + "      " + text.Substring(j, len2 - j).PadLeft(fill + len2 - j) + "\n";
            }
            catch (Exception e)
            {
            }

            return output;
        }

        internal static AlgorithmsPacket GetAlgorithmsPacket(byte[] data)
        {
            byte[] size = new byte[4];
            size = data.Take(size.Length).ToArray();
            Array.Reverse(size);
            int packetSize = BitConverter.ToInt32(size, 0);

            int dopunaSize = Convert.ToInt32(data[4]);

            // 6 jer je 4 size, 1 dopuna size, 1 paket identifier + 16 jer je to "cookie"
            // -2 dodatno jer je u size i paket identifier
            byte[] paket = data.Skip(6 + 16).Take(packetSize - dopunaSize - 2).ToArray();

            List<string> algoritmi = new List<string>();

            // 8 podataka jer nema language name-list dijela
            for (int i = 0; i < 8; i++)
            {
                // veličina
                byte[] sizeNum = new byte[4];
                sizeNum = paket.Take(size.Length).ToArray();
                Array.Reverse(sizeNum);
                int algSize = BitConverter.ToInt32(sizeNum, 0);

                // podaci
                byte[] alg = paket.Skip(4).Take(algSize).ToArray();

                // 4 zbog size i ostatak zbog samog pročitanog algoritma
                paket = paket.Skip(4 + algSize).ToArray();

                algoritmi.Add(Encoding.ASCII.GetString(alg));
            }

            string dh = algoritmi[0];

            string sig = algoritmi[1];

            string cry_cli = algoritmi[2];

            string cry_serv = algoritmi[3];

            string mac_cli = algoritmi[4];

            string mac_serv = algoritmi[5];

            string cli_compression = algoritmi[6];

            string serv_compression = algoritmi[7];

            return new AlgorithmsPacket
            {
                DH_algorithms = dh.Split(',').ToList(),
                ENCRYPTION_algorithms = cry_cli.Split(',').ToList(),
                MAC_algorithms = mac_cli.Split(',').ToList(),
                SIGNATURE_algorithms = sig.Split(',').ToList()
            };
        }

        internal static AlgorithmsUsed GetAlgorithmsForServerToUse(List<string> dH_ALGORITHMS, List<string> sIGNATURE_ALGORITHMS, List<string> eNCRYPTION_ALGORITHMS, List<string> mAC_ALGORITHMS, AlgorithmsPacket algoritmi)
        {
            string dh = "";
            string sig = "";
            string cry = "";
            string mac = "";

            foreach (string s in algoritmi.DH_algorithms)
            {
                if (dH_ALGORITHMS.Contains(s))
                {
                    dh = s;
                    break;
                }
            }

            foreach (string s in algoritmi.SIGNATURE_algorithms)
            {
                if (sIGNATURE_ALGORITHMS.Contains(s))
                {
                    sig = s;
                    break;
                }
            }

            foreach (string s in algoritmi.ENCRYPTION_algorithms)
            {
                if (eNCRYPTION_ALGORITHMS.Contains(s))
                {
                    cry = s;
                    break;
                }
            }

            foreach (string s in algoritmi.MAC_algorithms)
            {
                if (mAC_ALGORITHMS.Contains(s))
                {
                    mac = s;
                    break;
                }
            }

            return new AlgorithmsUsed { DH_algorithm = dh, ENCRYPTION_algorithm = cry, MAC_algorithm = mac, SIGNATURE_algorithm = sig };
        }

        public static AlgorithmsUsed GetAlgorithmsForClientToUse(List<string> dH_ALGORITHMS, List<string> sIGNATURE_ALGORITHMS, List<string> eNCRYPTION_ALGORITHMS, List<string> mAC_ALGORITHMS, AlgorithmsPacket algoritmi)
        {
            string dh = "";
            string sig = "";
            string cry = "";
            string mac = "";

            foreach (string s in dH_ALGORITHMS)
            {
                if (algoritmi.DH_algorithms.Contains(s))
                {
                    dh = s;
                    break;
                }
            }

            foreach (string s in sIGNATURE_ALGORITHMS)
            {
                if (algoritmi.SIGNATURE_algorithms.Contains(s))
                {
                    sig = s;
                    break;
                }
            }

            foreach (string s in eNCRYPTION_ALGORITHMS)
            {
                if (algoritmi.ENCRYPTION_algorithms.Contains(s))
                {
                    cry = s;
                    break;
                }
            }

            foreach (string s in mAC_ALGORITHMS)
            {
                if (algoritmi.MAC_algorithms.Contains(s))
                {
                    mac = s;
                    break;
                }
            }

            return new AlgorithmsUsed { DH_algorithm = dh, ENCRYPTION_algorithm = cry, MAC_algorithm = mac, SIGNATURE_algorithm = sig };
        }

        public static byte[] ComputeSHA1Hash_DH(string clientIdent, string serverIdent, byte[] ClientKEXINIT, byte[] ServerKEXINIT, string ServerCertPubKey,
                                            BigInteger e, BigInteger f, BigInteger K)
        {
            Debug.WriteLine("ci=" + clientIdent);
            Debug.WriteLine("si=" + serverIdent);
            Debug.WriteLine("CK=" + Convert.ToBase64String(ClientKEXINIT));
            Debug.WriteLine("SK=" + Convert.ToBase64String(ServerKEXINIT));
            Debug.WriteLine("sPub=" + ServerCertPubKey);
            Debug.WriteLine("e=" + e.ToString());
            Debug.WriteLine("f=" + f.ToString());
            Debug.WriteLine("K=" + K.ToString());

            var cIdn = Encoding.ASCII.GetBytes(clientIdent);
            var sIdn = Encoding.ASCII.GetBytes(serverIdent);
            var key = Encoding.ASCII.GetBytes(ServerCertPubKey);
            var e_array = e.ToByteArrayUnsigned();
            var f_array = f.ToByteArrayUnsigned();
            var K_array = K.ToByteArrayUnsigned();

            List<byte> arrayToHash = new List<byte>();

            arrayToHash.AddRange(cIdn);
            arrayToHash.AddRange(sIdn);
            arrayToHash.AddRange(ClientKEXINIT);
            arrayToHash.AddRange(ServerKEXINIT);
            arrayToHash.AddRange(key);
            arrayToHash.AddRange(e_array);
            arrayToHash.AddRange(f_array);
            arrayToHash.AddRange(K_array);

            byte[] hash;

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                hash = sha1.ComputeHash(arrayToHash.ToArray());
            }

            return hash;
        }

        public static EncryptionKeys GenerateEncryptionKeysFor3DES_CBC(string encryptionAl, string macAl, ref EncryptionAlgorithms encryptionAlgorithms, BigInteger K, string H, string sessionIdentifier)
        {
            // session identifier = H - ostaje isti čak i ako se ključevi promijene (i sam H je tada drugačiji...)

            /*
            Inicijalni IV (klijent -> poslužitelj) = hash (K || H || "A" || identifikator_sjednice)
            Inicijalni IV (poslužitelj -> klijent) = hash (K || H || "B" || identifikator_sjednice)
            Kljuc enkripcije (klijent -> poslužitelj) = hash (K || H || "C" || identifikator_sjednice)
            Kljuc enkripcije (poslužitelj -> klijent) = hash (K || H || "D" || identifikator_sjednice)
            MAC kljuc (klijent -> poslužitelj) = hash (K || H || "E" || identifikator_sjednice)
            MAC kljuc (klijent -> poslužitelj) = hash (K || H || "F" || identifikator_sjednice)
             */

            EncryptionKeys keys = new EncryptionKeys();
            List<byte> forHash = new List<byte>();

            var K_array = K.ToByteArrayUnsigned();
            var K_size = K_array.Length;
            var K_size_array = BitConverter.GetBytes(K_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(K_size_array);

            var H_array = Convert.FromBase64String(H);
            var H_size = H_array.Length;
            var H_size_array = BitConverter.GetBytes(H_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(H_size_array);

            var sessionIdent_array = Convert.FromBase64String(sessionIdentifier);
            var sessionIdent_size = sessionIdent_array.Length;
            var sessionIdent_size_array = BitConverter.GetBytes(sessionIdent_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(sessionIdent_size_array);

            var A = Convert.ToByte('A');
            var B = Convert.ToByte('B');
            var C = Convert.ToByte('C');
            var D = Convert.ToByte('D');
            var E = Convert.ToByte('E');
            var F = Convert.ToByte('F');

            var KH_array = new List<byte>();

            KH_array.AddRange(K_size_array);
            KH_array.AddRange(K_array);

            KH_array.AddRange(H_size_array);
            KH_array.AddRange(H_array);

            // vektor k -> s
            forHash.Clear();

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

                keys.vectorCS = key_list.Take(8).ToArray();
            }

            // vektor s -> k
            forHash.Clear();

            forHash.AddRange(KH_array);

            forHash.Add(B);

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

                keys.vectorSC = key_list.Take(8).ToArray();
            }

            switch (encryptionAl)
            {
                case "3des-cbc":
                    {
                        var encryKeys = Generate3DESKeys(K, H, sessionIdentifier);
                        keys.cryCS = encryKeys.cryCS;
                        keys.crySC = encryKeys.crySC;
                        encryptionAlgorithms.encryption = typeof(SSHHelper).GetMethod("Encrypt_Decrypt3DES_CBC");
                        break;
                    }
            }

            switch (macAl)
            {
                case "hmac-sha1":
                    {
                        EncryptionKeys encryKeys = GenerateHMAC_SHA1Keys(K, H, sessionIdentifier);
                        keys.MACKeyCS = encryKeys.MACKeyCS;
                        keys.MACKeySC = encryKeys.MACKeySC;
                        keys.MAClength = encryKeys.MAClength;
                        encryptionAlgorithms.MAC = typeof(SSHHelper).GetMethod("Compute_hmac_sha1");
                        break;
                    }
                case "gost28147":
                    {
                        EncryptionKeys encryKeys = GenerateGOST28147Keys(K, H, sessionIdentifier);
                        keys.MACKeyCS = encryKeys.MACKeyCS;
                        keys.MACKeySC = encryKeys.MACKeySC;
                        keys.MAClength = encryKeys.MAClength;
                        encryptionAlgorithms.MAC = typeof(SSHHelper).GetMethod("Compute_gost28147");
                        break;
                    }
            }

            return keys;
        }

        private static EncryptionKeys GenerateGOST28147Keys(BigInteger K, string H, string sessionIdentifier)
        {
            throw new NotImplementedException();
        }

        public static byte[] Compute_gost28147(byte[] paket, byte[] key)
        {
            Gost28147Mac gost = new Gost28147Mac();
            KeyParameter param = new KeyParameter(key);
            gost.Init(param);

            byte[] output = new byte[gost.GetMacSize()];
            gost.DoFinal(output, 0);

            return output;
        }

        public static byte[] Compute_hmac_sha1(byte[] paket, byte[] key)
        {
            HMACSHA1 hmacsha1 = new HMACSHA1(key);

            byte[] hashmessage = hmacsha1.ComputeHash(paket);

            return hashmessage;
        }

        private static EncryptionKeys GenerateHMAC_SHA1Keys(BigInteger K, string H, string sessionIdentifier)
        {
            EncryptionKeys keys = new EncryptionKeys();
            List<byte> forHash = new List<byte>();

            keys.MAClength = 20;

            var K_array = K.ToByteArrayUnsigned();
            var K_size = K_array.Length;
            var K_size_array = BitConverter.GetBytes(K_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(K_size_array);

            var H_array = Convert.FromBase64String(H);
            var H_size = H_array.Length;
            var H_size_array = BitConverter.GetBytes(H_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(H_size_array);

            var sessionIdent_array = Convert.FromBase64String(sessionIdentifier);
            var sessionIdent_size = sessionIdent_array.Length;
            var sessionIdent_size_array = BitConverter.GetBytes(sessionIdent_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(sessionIdent_size_array);

            var A = Convert.ToByte('A');
            var B = Convert.ToByte('B');
            var C = Convert.ToByte('C');
            var D = Convert.ToByte('D');
            var E = Convert.ToByte('E');
            var F = Convert.ToByte('F');

            var KH_array = new List<byte>();

            KH_array.AddRange(K_size_array);
            KH_array.AddRange(K_array);

            KH_array.AddRange(H_size_array);
            KH_array.AddRange(H_array);

            // MAC ključ k -> s
            forHash.Clear();

            forHash.AddRange(KH_array);

            forHash.Add(E);

            forHash.AddRange(sessionIdent_array);

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                keys.MACKeyCS = sha1.ComputeHash(forHash.ToArray());
            }

            // MAC ključ s -> k
            forHash.Clear();

            forHash.AddRange(KH_array);

            forHash.Add(F);

            forHash.AddRange(sessionIdent_array);

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                keys.MACKeySC = sha1.ComputeHash(forHash.ToArray());
            }

            return keys;
        }

        private static EncryptionKeys Generate3DESKeys(BigInteger K, string H, string sessionIdentifier)
        {
            EncryptionKeys keys = new EncryptionKeys();
            List<byte> forHash = new List<byte>();

            var K_array = K.ToByteArrayUnsigned();
            var K_size = K_array.Length;
            var K_size_array = BitConverter.GetBytes(K_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(K_size_array);

            var H_array = Convert.FromBase64String(H);
            var H_size = H_array.Length;
            var H_size_array = BitConverter.GetBytes(H_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(H_size_array);

            var sessionIdent_array = Convert.FromBase64String(sessionIdentifier);
            var sessionIdent_size = sessionIdent_array.Length;
            var sessionIdent_size_array = BitConverter.GetBytes(sessionIdent_size);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(sessionIdent_size_array);

            var A = Convert.ToByte('A');
            var B = Convert.ToByte('B');
            var C = Convert.ToByte('C');
            var D = Convert.ToByte('D');
            var E = Convert.ToByte('E');
            var F = Convert.ToByte('F');

            var KH_array = new List<byte>();

            KH_array.AddRange(K_size_array);
            KH_array.AddRange(K_array);

            KH_array.AddRange(H_size_array);
            KH_array.AddRange(H_array);

            // 3DES ključ 192b = 24B
            // aes256 je 256 bita - 32B

            // enkripcija k -> s
            forHash.Clear();

            forHash.AddRange(KH_array);

            forHash.Add(C);

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

                keys.cryCS = key_list.Take(24).ToArray();
            }

            // enkripcija s -> k
            forHash.Clear();

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

                keys.crySC = key_list.Take(24).ToArray();
            }

            return keys;
        }

        /// <summary>
        /// Encryption using 3DES algorithm in CBC mode
        /// </summary>
        /// <param name="message">Input message bytes</param>
        /// <param name="isEncryption">true for encrypting, false for decrypting</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="key">key for encryption</param>
        /// <returns>Encrypted message bytes</returns>
        public static byte[] Encrypt_Decrypt3DES_CBC(byte[] message, byte[] key, byte[] iv, bool isEncryption)
        {
            Debug.WriteLine("msg=" + Convert.ToBase64String(message));

            DesEdeEngine desedeEngine = new DesEdeEngine();
            BufferedBlockCipher bufferedCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(desedeEngine), new Pkcs7Padding());
            // 192 bita ključ = 24 bajta
            KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", key);
            ParametersWithIV keyWithIV = new ParametersWithIV(keyparam, iv);

            byte[] output = new byte[bufferedCipher.GetOutputSize(message.Length)];
            bufferedCipher.Init(isEncryption, keyWithIV);
            output = bufferedCipher.DoFinal(message);

            Debug.WriteLine("msgENCRY=" + Convert.ToBase64String(output));

            return output;
        }

        internal static byte[] ComputeSHA2Hash_ECDH(string clientIdent, string serverIdent, byte[] ClientKEXINIT, byte[] ServerKEXINIT, string ServerCertPubKey, BigInteger x_c, BigInteger y_c, BigInteger x, BigInteger y, BigInteger K)
        {
            Debug.WriteLine("ci=" + clientIdent);
            Debug.WriteLine("si=" + serverIdent);
            Debug.WriteLine("CK=" + Convert.ToBase64String(ClientKEXINIT));
            Debug.WriteLine("SK=" + Convert.ToBase64String(ServerKEXINIT));
            Debug.WriteLine("sPub=" + ServerCertPubKey);
            Debug.WriteLine("x_r=" + x_c.ToString());
            Debug.WriteLine("y_r=" + y_c.ToString());
            Debug.WriteLine("x=" + x.ToString());
            Debug.WriteLine("y=" + y.ToString());
            Debug.WriteLine("K=" + K.ToString());

            var cIdn = Encoding.ASCII.GetBytes(clientIdent);
            var sIdn = Encoding.ASCII.GetBytes(serverIdent);
            var key = Encoding.ASCII.GetBytes(ServerCertPubKey);
            var x_r_array = x_c.ToByteArrayUnsigned();
            var y_r_array = y_c.ToByteArrayUnsigned();
            var x_array = x.ToByteArrayUnsigned();
            var y_array = y.ToByteArrayUnsigned();
            var K_array = K.ToByteArrayUnsigned();

            List<byte> arrayToHash = new List<byte>();

            arrayToHash.AddRange(cIdn);
            arrayToHash.AddRange(sIdn);
            arrayToHash.AddRange(ClientKEXINIT);
            arrayToHash.AddRange(ServerKEXINIT);
            arrayToHash.AddRange(key);
            arrayToHash.AddRange(x_r_array);
            arrayToHash.AddRange(y_r_array);
            arrayToHash.AddRange(x_array);
            arrayToHash.AddRange(y_array);
            arrayToHash.AddRange(K_array);

            byte[] hash;

            using (SHA256Managed sha256 = new SHA256Managed())
            {
                hash = sha256.ComputeHash(arrayToHash.ToArray());
            }

            return hash;
        }

        internal static byte[] ComputeSHA2Hash_DH(string clientIdent, string serverIdent, byte[] ClientKEXINIT, byte[] ServerKEXINIT, string ServerCertPubKey, BigInteger e, BigInteger f, BigInteger K)
        {
            Debug.WriteLine("ci=" + clientIdent);
            Debug.WriteLine("si=" + serverIdent);
            Debug.WriteLine("CK=" + Convert.ToBase64String(ClientKEXINIT));
            Debug.WriteLine("SK=" + Convert.ToBase64String(ServerKEXINIT));
            Debug.WriteLine("sPub=" + ServerCertPubKey);
            Debug.WriteLine("e=" + e.ToString());
            Debug.WriteLine("f=" + f.ToString());
            Debug.WriteLine("K=" + K.ToString());

            var cIdn = Encoding.ASCII.GetBytes(clientIdent);
            var sIdn = Encoding.ASCII.GetBytes(serverIdent);
            var key = Encoding.ASCII.GetBytes(ServerCertPubKey);
            var e_array = e.ToByteArrayUnsigned();
            var f_array = f.ToByteArrayUnsigned();
            var K_array = K.ToByteArrayUnsigned();

            List<byte> arrayToHash = new List<byte>();

            arrayToHash.AddRange(cIdn);
            arrayToHash.AddRange(sIdn);
            arrayToHash.AddRange(ClientKEXINIT);
            arrayToHash.AddRange(ServerKEXINIT);
            arrayToHash.AddRange(key);
            arrayToHash.AddRange(e_array);
            arrayToHash.AddRange(f_array);
            arrayToHash.AddRange(K_array);

            byte[] hash;

            using (SHA256Managed sha256 = new SHA256Managed())
            {
                hash = sha256.ComputeHash(arrayToHash.ToArray());
            }

            return hash;
        }

        internal static byte[] ComputeSHA1Hash_ECDH(string clientIdent, string serverIdent, byte[] ClientKEXINIT, byte[] ServerKEXINIT, string ServerCertPubKey, BigInteger x_c, BigInteger y_c, BigInteger x, BigInteger y, BigInteger K)
        {
            var cIdn = Encoding.ASCII.GetBytes(clientIdent);
            var sIdn = Encoding.ASCII.GetBytes(serverIdent);
            var key = Encoding.ASCII.GetBytes(ServerCertPubKey);
            var x_r_array = x_c.ToByteArrayUnsigned();
            var y_r_array = y_c.ToByteArrayUnsigned();
            var x_array = x.ToByteArrayUnsigned();
            var y_array = y.ToByteArrayUnsigned();
            var K_array = K.ToByteArrayUnsigned();

            List<byte> arrayToHash = new List<byte>();

            arrayToHash.AddRange(cIdn);
            arrayToHash.AddRange(sIdn);
            arrayToHash.AddRange(ClientKEXINIT);
            arrayToHash.AddRange(ServerKEXINIT);
            arrayToHash.AddRange(key);
            arrayToHash.AddRange(x_r_array);
            arrayToHash.AddRange(y_r_array);
            arrayToHash.AddRange(x_array);
            arrayToHash.AddRange(y_array);
            arrayToHash.AddRange(K_array);

            byte[] hash;

            using (SHA1Managed sha1 = new SHA1Managed())
            {
                hash = sha1.ComputeHash(arrayToHash.ToArray());
            }

            return hash;
        }
    }
}