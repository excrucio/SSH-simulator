using Org.BouncyCastle;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public class Client
    {
        public List<string> DH_ALGORITHMS = new List<string> { "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1" };
        public List<string> SIGNATURE_ALGORITHMS = new List<string> { "ssh-dss" };
        public List<string> ENCRYPTION_ALGORITHMS = new List<string> { "3des-cbc" };
        public List<string> MAC_ALGORITHMS = new List<string> { "hmac-sha1" };

        private string _clientIdent;
        private string _serverIdent;
        private byte[] _clientKEXINIT;
        private byte[] _serverKEXINIT;
        private int _windowSize;
        private int _remoteChannel;
        private int _localChannel;

        private List<byte> _dataReceived = new List<byte>();
        private int _lastDataSizeReceived;

        private AsymmetricCipherKeyPair DH_KeyPair;
        private ExchangeParameters ex_params = new ExchangeParameters();

        private EncryptionKeys keys = new EncryptionKeys();
        private EncryptionAlgorithms encryptionAlgorithms = new EncryptionAlgorithms();

        private MemoryStream stream;
        private StreamReader reader;
        private StreamWriter writer;
        private MainWindow mainWindow;
        private AlgorithmsUsed algorithmsToUse = new AlgorithmsUsed();
        private AlgorithmsPacket algorithmsReceived = new AlgorithmsPacket();

        public Client(MemoryStream ms, MainWindow mw)
        {
            mainWindow = mw;
            stream = ms;
            reader = new StreamReader(ms);
            writer = new StreamWriter(ms);
        }

        public AlgorithmsUsed GetAlgorithmsToUse()
        {
            return algorithmsToUse;
        }

        public void SendIdentifierToServer()
        {
            try
            {
                writer.WriteLine(mainWindow.textBox_clientIdent.Text);
                writer.Flush();
            }
            catch (Exception e)
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Nije moguće kontaktirati server!";
                return;
            }

            _clientIdent = mainWindow.textBox_clientIdent.Text;

            mainWindow.boolRetResult = true;
            mainWindow.textBox_info.Text = "Klijent poslao identifikacijski paket\n\n";
            return;
        }

        public void ReadServerId()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);
                string line = reader.ReadLine();
                stream.Seek(0, SeekOrigin.Begin);

                mainWindow.boolRetResult = true;
                if (!line.StartsWith("SSH-2.0-"))
                {
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = "Not valid identifier!";
                    return;
                }

                _serverIdent = line;

                mainWindow.textBox_client.Text = line;
                mainWindow.textBox_client_decoded.Text = line;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendKEXINIT()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                Random rnd = new Random();

                List<byte> payload = new List<byte>();

                // identifikator paketa
                var ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEXINIT);
                payload.Add(ident[0]);

                // cookie
                byte[] random = new byte[16];
                rnd.NextBytes(random);

                payload.AddRange(random);

                // popis algoritama odvojeni s po 3 "prazna" bajta
                //dh, dh server, potpis, potpis server, enkripcija, enkripcija server, mac, mac server, kompresija, kompresija server

                if ((bool)mainWindow.checkBox_ecdh_sha2_nistp521.IsChecked)
                {
                    DH_ALGORITHMS.Insert(0, "ecdh-sha2-nistp521");
                }

                if ((bool)mainWindow.checkBox_ssh_rsa.IsChecked)
                {
                    SIGNATURE_ALGORITHMS.Insert(0, "ssh-rsa");
                }

                if ((bool)mainWindow.checkBox_ecdsa_ssh2_nistp384.IsChecked)
                {
                    SIGNATURE_ALGORITHMS.Insert(0, "ecdsa-ssh2-nistp384");
                }

                if ((bool)mainWindow.checkBox_blowfish_ctr.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Add("blowfish-ctr");
                }

                if ((bool)mainWindow.checkBox_aes256_cbc.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Insert(0, "aes256-cbc");
                }

                if ((bool)mainWindow.checkBox_hmac_sha2.IsChecked)
                {
                    MAC_ALGORITHMS.Add("hmac-sha2");
                }

                if ((bool)mainWindow.checkBox_gost28147.IsChecked)
                {
                    MAC_ALGORITHMS.Add("gost28147");
                }

                byte[] dh = Encoding.ASCII.GetBytes(string.Join(",", DH_ALGORITHMS));
                byte[] sig = Encoding.ASCII.GetBytes(string.Join(",", SIGNATURE_ALGORITHMS));
                byte[] cry = Encoding.ASCII.GetBytes(string.Join(",", ENCRYPTION_ALGORITHMS));
                byte[] mac = Encoding.ASCII.GetBytes(string.Join(",", MAC_ALGORITHMS));
                byte[] compress = Encoding.ASCII.GetBytes("none");

                byte[] delimiter = new byte[3];

                List<byte> lista = new List<byte>();

                lista.AddRange(payload);

                delimiter = BitConverter.GetBytes(dh.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(dh);

                delimiter = BitConverter.GetBytes(sig.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(sig);

                delimiter = BitConverter.GetBytes(cry.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(cry);
                lista.AddRange(delimiter);
                lista.AddRange(cry);

                delimiter = BitConverter.GetBytes(mac.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(mac);
                lista.AddRange(delimiter);
                lista.AddRange(mac);

                delimiter = BitConverter.GetBytes(compress.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(compress);
                lista.AddRange(delimiter);
                lista.AddRange(compress);

                // dodati - first KEXINIT packet folows = false
                lista.Add(0x0);

                // sve to spojiti i to je korisni dio paketa

                byte[] all = lista.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                _clientKEXINIT = paket;

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;

            mainWindow.textBox_info.AppendText("Klijent poslao KEXINIT paket\n\n");
        }

        public void ReadKEXINIT()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] size = new byte[4];
                stream.Read(size, 0, size.Length);
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                byte[] paket = new byte[packetSize + size.Length];

                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(paket, 0, packetSize + size.Length);

                _serverKEXINIT = paket;

                int tip = Convert.ToInt32(paket[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                AlgorithmsPacket algoritmi = SSHHelper.GetAlgorithmsPacket(paket);

                algorithmsReceived = algoritmi;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SetAlgorithms()
        {
            try
            {
                AlgorithmsUsed usedAl = SSHHelper.GetAlgorithmsForClientToUse(DH_ALGORITHMS, SIGNATURE_ALGORITHMS, ENCRYPTION_ALGORITHMS, MAC_ALGORITHMS, algorithmsReceived);

                algorithmsToUse = usedAl;

                mainWindow.textBox_info.AppendText("Klijent utvrđuje koje algoritme da koristi na osnovu primljenih paketa\n\n");

                if (!(algorithmsToUse.DH_algorithm != null && algorithmsToUse.ENCRYPTION_algorithm != null
                      && algorithmsToUse.MAC_algorithm != null && algorithmsToUse.SIGNATURE_algorithm != null))

                {
                    mainWindow.retResult = "Neuspješan dogovor oko korištenja algoritama!";
                    mainWindow.boolRetResult = false;
                }
            }
            catch
            {
                mainWindow.retResult = "Neuspješan dogovor oko korištenja algoritama!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void CalculateDH()
        {
            try
            {
                mainWindow.textBox_info.AppendText("Klijent računa parametre za Diffie-Hellman razmjenu\n\n");

                // what dh to calculate

                switch (algorithmsToUse.DH_algorithm)
                {
                    case "ecdh-sha2-nistp521":
                        {
                            Calculate_ecdh_sha2_nistp521();

                            var senderPrivate = ((ECPrivateKeyParameters)DH_KeyPair.Private).D.ToByteArrayUnsigned();
                            var senderPublic = ((ECPublicKeyParameters)DH_KeyPair.Public).Q.GetEncoded();
                            mainWindow.textBox_x.Text = BitConverter.ToString(senderPrivate).Replace("-", "").ToLower();
                            mainWindow.textBox_e.Text = BitConverter.ToString(senderPublic).Replace("-", "").ToLower();

                            ex_params.x_c = ((ECPublicKeyParameters)DH_KeyPair.Public).Q.X.ToBigInteger();
                            ex_params.y_c = ((ECPublicKeyParameters)DH_KeyPair.Public).Q.Y.ToBigInteger();

                            mainWindow.label_privatni_kljuc_DH.Content = "DH privatni ključ";
                            mainWindow.label_javni_kljuc.Content = "DH javni ključ";

                            mainWindow.label_privatni_kljuc.Content = "Tajni ključ K";
                            break;
                        }
                    case "diffie-hellman-group1-sha1":
                        {
                            CalculateDH_g1();

                            var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                            var publicKey = DH_KeyPair.Public as DHPublicKeyParameters;

                            ex_params.e = publicKey.Y;

                            mainWindow.textBox_x.Text = privateKey.X.ToString();
                            mainWindow.textBox_e.Text = publicKey.Y.ToString();
                            break;
                        }

                    case "diffie-hellman-group14-sha1":
                        {
                            CalculateDH_g14();

                            var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                            var publicKey = DH_KeyPair.Public as DHPublicKeyParameters;

                            ex_params.e = publicKey.Y;

                            mainWindow.textBox_x.Text = privateKey.X.ToString();
                            mainWindow.textBox_e.Text = publicKey.Y.ToString();
                            break;
                        }
                }
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Could not generate keys!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        private void Calculate_ecdh_sha2_nistp521()
        {
            AsymmetricCipherKeyPair keyPair = ecdh_sha2_nistp521.getKeyPair();

            mainWindow.textBox_cli_mod_p.Text = "nistp521";
            mainWindow.label_krivulja.Content = "krivulja";
            mainWindow.textBox_cli_g.Text = ((ECKeyParameters)keyPair.Public).Parameters.G.ToString();

            DH_KeyPair = keyPair;
        }

        private void CalculateDH_g1()
        {
            BigInteger p = new BigInteger(DHg1.p_hex, 16);
            BigInteger g = new BigInteger(DHg1.g_hex, 16);

            ex_params.p = p;

            var kp = GetDHKeyPair(p, g);

            DH_KeyPair = kp;
        }

        private void CalculateDH_g14()
        {
            BigInteger p = new BigInteger(DHg14.p_hex, 16);
            BigInteger g = new BigInteger(DHg14.g_hex, 16);

            ex_params.p = p;

            var kp = GetDHKeyPair(p, g);

            DH_KeyPair = kp;
        }

        private AsymmetricCipherKeyPair GetDHKeyPair(BigInteger p, BigInteger g)
        {
            mainWindow.textBox_cli_mod_p.Text = p.ToString();
            mainWindow.textBox_cli_g.Text = g.ToString();

            DHParameters importedParameters = new DHParameters(p, g);

            var keyGen = GeneratorUtilities.GetKeyPairGenerator("DH");

            KeyGenerationParameters kgp = new DHKeyGenerationParameters(new SecureRandom(), importedParameters);
            keyGen.Init(kgp);

            AsymmetricCipherKeyPair KeyPair = keyGen.GenerateKeyPair();

            return KeyPair;
        }

        public void SendDHPacket()
        {
            // koji dh paket?? "obični" ili ECDH?
            bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");

            if (ecdhPacket)
            {
                SendECDHPacket();
                return;
            }

            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;
                if (ecdhPacket)
                {
                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEX_ECDH_INIT);
                }
                else
                {
                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEXDH_INIT);
                }
                payload.Add(ident[0]);

                byte[] publicKey = GetKEXDHPublicKeyBytes();

                List<byte> lista = new List<byte>();

                lista.AddRange(payload);

                lista.AddRange(publicKey);

                byte[] all = lista.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;

            mainWindow.textBox_info.AppendText("Klijent poslao KEXDH_INIT paket\n\n");
        }

        private void SendECDHPacket()
        {
            /*
            byte      SSH_MSG_KEXDH_INIT
            mpint     x
            mpint     y

            */

            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;

                ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEX_ECDH_INIT);

                payload.Add(ident[0]);

                byte[] publicKey = GetKEXDHPublicKeyBytes();

                List<byte> lista = new List<byte>();

                lista.AddRange(payload);

                lista.AddRange(publicKey);

                byte[] all = lista.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;

            mainWindow.textBox_info.AppendText("Klijent poslao KEX_ECDH_INIT paket\n\n");
        }

        private byte[] GetKEXDHPublicKeyBytes()
        {
            bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");
            if (!ecdhPacket)
            {
                var pub = DH_KeyPair.Public as DHPublicKeyParameters;
                var publicKey = pub.Y.ToByteArrayUnsigned();
                var pubLength = publicKey.Length;

                var size = BitConverter.GetBytes(pubLength);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                List<byte> rezultat = new List<byte>();

                rezultat.AddRange(size);
                rezultat.AddRange(publicKey);

                return rezultat.ToArray();
            }
            else
            {
                // inače se radi o ECDH...
                var pub = DH_KeyPair.Public as ECPublicKeyParameters;
                var xPub = pub.Q.X.ToBigInteger().ToByteArrayUnsigned();
                var yPub = pub.Q.Y.ToBigInteger().ToByteArrayUnsigned();
                var xPubLength = xPub.Length;
                var yPubLength = yPub.Length;

                var xsize = BitConverter.GetBytes(xPubLength);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(xsize);

                var ysize = BitConverter.GetBytes(yPubLength);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(ysize);

                List<byte> rezultat = new List<byte>();

                rezultat.AddRange(xsize);
                rezultat.AddRange(xPub);
                rezultat.AddRange(ysize);
                rezultat.AddRange(yPub);

                return rezultat.ToArray();
            }
        }

        public void ReadDHPacket()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                // koji dh paket?? "obični" ili ECDH?
                bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");

                if (ecdhPacket)
                {
                    ReadECDHPacket();
                    return;
                }

                byte[] size = new byte[4];
                stream.Read(size, 0, size.Length);
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                byte[] paket = new byte[packetSize + size.Length];

                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(paket, 0, packetSize + size.Length);

                int tip = Convert.ToInt32(paket[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());
                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi javni ključ poslužitelja
                // paket - cijeli paket i sve
                // duljina paketa - bez sebe
                // uzmi samo dio s info: duljinaPaketa - duljinaDopune - 1

                int dopunaSize = Convert.ToInt32(paket[4]);

                // 6 jer je 4 size, 1 dopuna size, 1 paket identifier
                var K_S_size_array = paket.Skip(6).Take(4).ToArray();
                Array.Reverse(K_S_size_array);
                int K_S_size = BitConverter.ToInt32(K_S_size_array, 0);
                var K_S_array = paket.Skip(6 + 4).Take(K_S_size).ToArray();

                paket = paket.Skip(6 + 4 + K_S_size).ToArray();

                // pokupi f
                // 4 size
                var f_size_array = paket.Take(4).ToArray();
                Array.Reverse(f_size_array);
                int f_size = BitConverter.ToInt32(f_size_array, 0);
                var f_array = paket.Skip(4).Take(f_size).ToArray();
                var f_param = new BigInteger(f_array);

                paket = paket.Skip(4 + f_size).ToArray();

                // pokupi potpis - s
                // 4 size
                var s_size_array = paket.Take(4).ToArray();
                Array.Reverse(s_size_array);
                int s_size = BitConverter.ToInt32(s_size_array, 0);
                var s_param = paket.Skip(4).Take(s_size).ToArray();

                var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                // K = f^x mod p
                var K = f_param.ModPow(privateKey.X, ex_params.p);

                mainWindow.textBox_cli_K.Text = K.ToString();

                ex_params.K = K;
                ex_params.f = f_param;

                mainWindow.textBox_ser_K.Text = ex_params.K.ToString();

                switch (algorithmsToUse.SIGNATURE_algorithm)
                {
                    case "ssh-rsa":
                        {
                            var K_S_param = Encoding.ASCII.GetString(K_S_array);

                            mainWindow.textBox_ser_pub_key.Text = BitConverter.ToString(Convert.FromBase64String(K_S_param)).Replace("-", "").ToLower();

                            // izračunati hash
                            byte[] hash = null;

                            Debug.WriteLine("Sada klijent:");
                            hash = SSHHelper.ComputeSHA1Hash(_clientIdent, _serverIdent, _clientKEXINIT, _serverKEXINIT, K_S_param, ex_params.e, ex_params.f, ex_params.K);

                            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

                            using (StreamReader txtStream = File.OpenText(@"ServerCert\server_rsa.pem"))
                            {
                                PemReader reader = new PemReader(txtStream);
                                AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)reader.ReadObject();
                                decryptEngine.Init(false, pair.Public);
                            }

                            var sig = Encoding.ASCII.GetString(s_param);

                            mainWindow.textBox_sig_ser.Text = BitConverter.ToString(s_param).Replace("-", "").ToLower();

                            var dec = Convert.FromBase64String(sig);
                            var decrypted = decryptEngine.ProcessBlock(dec, 0, dec.Length);

                            var hashBase64 = Convert.ToBase64String(hash);
                            var sigHashBase64 = Convert.ToBase64String(decrypted);

                            ex_params.H = hashBase64;

                            mainWindow.textBox_cli_H.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();

                            if (hashBase64 != sigHashBase64)
                            {
                                mainWindow.boolRetResult = false;
                                mainWindow.retResult = "Hash paketa se razlikuje!";
                                return;
                            }

                            break;
                        }

                    case "ecdsa-ssh2-nistp384":
                        {
                            var K_S_param = Encoding.ASCII.GetString(K_S_array);

                            // izračunati hash
                            byte[] computed_hash = null;

                            computed_hash = SSHHelper.ComputeSHA2Hash_DH(_clientIdent, _serverIdent, _clientKEXINIT, _serverKEXINIT, K_S_param, ex_params.e, ex_params.f, ex_params.K);

                            string hexPubFromFile = File.ReadAllLines(@"ServerCert\ECDSA.public")[0];

                            // provjeri je li javni ključ kako treba
                            if (K_S_param != hexPubFromFile)
                            {
                                mainWindow.retResult = "Javni ključ servera neispravan!";
                                mainWindow.boolRetResult = false;
                                return;
                            }

                            mainWindow.textBox_sig_ser.Text = BitConverter.ToString(s_param).Replace("-", "").ToLower();

                            string pubHex = hexPubFromFile;
                            var bytesKey = Enumerable.Range(0, pubHex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(pubHex.Substring(x, 2), 16)).ToArray();

                            CngKey key = CngKey.Import(bytesKey, CngKeyBlobFormat.EccPublicBlob);
                            ECDsaCng dsa = new ECDsaCng(key);

                            /*
                            var sig_base64 = Encoding.ASCII.GetString(s_param);

                            var signature_array = Convert.FromBase64String(sig_base64);
                            */

                            var signature_array = s_param;

                            // TODO !! zašto ne prolazi???

                            bool isti = mainWindow.sig.SequenceEqual(signature_array);
                            bool hist = mainWindow.hash.SequenceEqual(computed_hash);
                            if (dsa.VerifyData(computed_hash, signature_array))
                            {
                                mainWindow.boolRetResult = false;
                                mainWindow.retResult = "Hash paketa se razlikuje!";
                                return;
                            }

                            var hashBase64 = Convert.ToBase64String(computed_hash);

                            ex_params.H = hashBase64;

                            byte[] pub_key = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);

                            mainWindow.textBox_ser_pub_key.Text = BitConverter.ToString(pub_key).Replace("-", "").ToLower();
                            mainWindow.textBox_cli_H.Text = BitConverter.ToString(computed_hash).Replace("-", "").ToLower();

                            break;
                        }
                }

                stream.Seek(0, SeekOrigin.Begin);

                mainWindow.ShowDialogMsg("Uspješno autentificiran server!");
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }
        }

        private void ReadECDHPacket()
        {
            /*
            byte      SSH_MSG_KEX_ECDH_REPLY
            string    server public host key
            mpint     x
            mpint     y
            string    signature of H
            */

            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] size = new byte[4];
                stream.Read(size, 0, size.Length);
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                byte[] paket = new byte[packetSize + size.Length];

                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(paket, 0, packetSize + size.Length);

                int tip = Convert.ToInt32(paket[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());
                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                switch (algorithmsToUse.SIGNATURE_algorithm)
                {
                    case "ssh-rsa":
                        {
                            // pokupi javni ključ poslužitelja
                            // paket - cijeli paket i sve
                            // duljina paketa - bez sebe
                            // uzmi samo dio s info: duljinaPaketa - duljinaDopune - 1

                            int dopunaSize = Convert.ToInt32(paket[4]);

                            // 6 jer je 4 size, 1 dopuna size, 1 paket identifier
                            var K_S_size_array = paket.Skip(6).Take(4).ToArray();
                            Array.Reverse(K_S_size_array);
                            int K_S_size = BitConverter.ToInt32(K_S_size_array, 0);
                            var K_S_array = paket.Skip(6 + 4).Take(K_S_size).ToArray();
                            var K_S_param = Encoding.ASCII.GetString(K_S_array);

                            paket = paket.Skip(6 + 4 + K_S_size).ToArray();

                            mainWindow.textBox_ser_pub_key.Text = BitConverter.ToString(Convert.FromBase64String(K_S_param)).Replace("-", "").ToLower();

                            // pokupi x i y
                            // 4 size
                            var x_size_array = paket.Take(4).ToArray();
                            Array.Reverse(x_size_array);
                            int x_size = BitConverter.ToInt32(x_size_array, 0);
                            var x_array = paket.Skip(4).Take(x_size).ToArray();
                            var x_param = new BigInteger(1, x_array);

                            paket = paket.Skip(4 + x_size).ToArray();

                            var y_size_array = paket.Take(4).ToArray();
                            Array.Reverse(y_size_array);
                            int y_size = BitConverter.ToInt32(y_size_array, 0);
                            var y_array = paket.Skip(4).Take(y_size).ToArray();
                            var y_param = new BigInteger(1, y_array);

                            paket = paket.Skip(4 + y_size).ToArray();

                            // pokupi potpis - s
                            // 4 size
                            var s_size_array = paket.Take(4).ToArray();
                            Array.Reverse(s_size_array);
                            int s_size = BitConverter.ToInt32(s_size_array, 0);
                            var s_param = paket.Skip(4).Take(s_size).ToArray();

                            var privateKey = DH_KeyPair.Private as ECPrivateKeyParameters;

                            BigInteger sharedKey = ecdh_sha2_nistp521.CalculateSharedKey(x_param, y_param, privateKey);

                            ex_params.K = sharedKey;
                            ex_params.K = sharedKey;
                            ex_params.x = x_param;
                            ex_params.y = y_param;

                            mainWindow.textBox_cli_K.Text = sharedKey.ToString();
                            mainWindow.textBox_ser_K.Text = ex_params.K.ToString();

                            // izračunati hash
                            byte[] hash = null;

                            Debug.WriteLine("Sada klijent:");
                            hash = SSHHelper.ComputeSHA2Hash_ecdh(_clientIdent, _serverIdent, _clientKEXINIT, _serverKEXINIT, K_S_param, ex_params.x_c, ex_params.y_c, ex_params.x, ex_params.y, ex_params.K);

                            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

                            using (StreamReader txtStream = File.OpenText(@"ServerCert\server_rsa.pem"))
                            {
                                PemReader reader = new PemReader(txtStream);
                                AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)reader.ReadObject();
                                decryptEngine.Init(false, pair.Public);
                            }

                            var sig = Encoding.ASCII.GetString(s_param);

                            mainWindow.textBox_sig_ser.Text = BitConverter.ToString(s_param).Replace("-", "").ToLower();

                            var dec = Convert.FromBase64String(sig);
                            var decrypted = decryptEngine.ProcessBlock(dec, 0, dec.Length);

                            var hashBase64 = Convert.ToBase64String(hash);
                            var sigHashBase64 = Convert.ToBase64String(decrypted);

                            ex_params.H = hashBase64;

                            mainWindow.textBox_cli_H.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();

                            if (hashBase64 != sigHashBase64)
                            {
                                mainWindow.boolRetResult = false;
                                mainWindow.retResult = "Hash paketa se razlikuje!";
                                return;
                            }

                            break;
                        }

                    case "ecdsa-ssh2-nistp384":
                        {
                            // TODO ! -.-
                            break;
                        }
                }

                stream.Seek(0, SeekOrigin.Begin);

                mainWindow.ShowDialogMsg("Uspješno autentificiran server!");
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }
        }

        public void SendNEWKEYSPacket()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_NEWKEYS);

                payload.Add(ident[0]);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                mainWindow.textBox_info.AppendText("Klijent šalje NEWKEYS paket\n\n");

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }
        }

        public void ReadNEWKEYSPacket()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] size = new byte[4];
                stream.Read(size, 0, size.Length);
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                byte[] paket = new byte[packetSize + size.Length];

                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(paket, 0, packetSize + size.Length);

                int tip = Convert.ToInt32(paket[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void GenerateEncryptionKeys()
        {
            try
            {
                mainWindow.textBox_info.AppendText("Klijent računa ključeve za enkripciju\n\n");

                mainWindow.label_cli_cry.Content = algorithmsToUse.ENCRYPTION_algorithm;
                mainWindow.label_cli_mac.Content = algorithmsToUse.MAC_algorithm;

                mainWindow.textBox_cli_K1.Text = ex_params.K.ToString();
                mainWindow.textBox_cli_H1.Text = BitConverter.ToString(Convert.FromBase64String(ex_params.H)).Replace("-", "").ToLower();

                switch (algorithmsToUse.ENCRYPTION_algorithm)
                {
                    case "3des-cbc":
                        {
                            keys = SSHHelper.GenerateEncryptionKeysFor3DES_CBC(algorithmsToUse.ENCRYPTION_algorithm, algorithmsToUse.MAC_algorithm, ref encryptionAlgorithms, ex_params.K, ex_params.H, ex_params.H);
                            break;
                        }
                }

                mainWindow.textBox_cli_c_s.Text = BitConverter.ToString(keys.vectorCS).Replace("-", "").ToLower();
                mainWindow.textBox_cli_s_c.Text = BitConverter.ToString(keys.vectorSC).Replace("-", "").ToLower();
                mainWindow.textBox_cli_cry_c_s.Text = BitConverter.ToString(keys.cryCS).Replace("-", "").ToLower();
                mainWindow.textBox_cli_cry_s_c.Text = BitConverter.ToString(keys.crySC).Replace("-", "").ToLower();
                mainWindow.textBox_cli_MAC_c_s.Text = BitConverter.ToString(keys.MACKeyCS).Replace("-", "").ToLower();
                mainWindow.textBox_cli_MAC_s_c.Text = BitConverter.ToString(keys.MACKeySC).Replace("-", "").ToLower();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Klijent nije uspio izgenerirati ključeve!";
            }

            mainWindow.boolRetResult = true;
        }

        public void SendServiceRequestPacket()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje SERVICE_REQUEST paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_SERVICE_REQUEST);

                payload.Add(ident[0]);

                string req = "ssh-userauth";
                byte[] req_array = Encoding.ASCII.GetBytes(req);
                var size = BitConverter.GetBytes(req.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(req_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadServiceAcceptPacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);

                    if ((identifiers)tip != identifiers.SSH_MSG_SERVICE_ACCEPT)
                    {
                        mainWindow.boolRetResult = false;
                        mainWindow.retResult = "Krivi paket!";
                        return;
                    }
                }

                /*
                // pokupi vrstu autentifikacije
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa + 4 veličina stringa
                byte[] infoSize_array = new byte[4];
                infoSize_array = paket.Skip(6).Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                int infoSize = BitConverter.ToInt32(infoSize_array, 0);
                authResponse = Encoding.ASCII.GetString(paket_decoded.Skip(6 + 4).Take(infoSize).ToArray());
                */

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendAuth()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje USERAUTH_REQUEST paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_USERAUTH_REQUEST);

                payload.Add(ident[0]);

                string username = mainWindow.textBox_login.Text;

                byte[] username_array = Encoding.UTF8.GetBytes(username);
                var size = BitConverter.GetBytes(username.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(username_array);

                string service = "ssh-connection";

                byte[] service_array = Encoding.ASCII.GetBytes(service);
                size = BitConverter.GetBytes(service.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(service_array);

                string method = "password";
                byte[] method_array = Encoding.ASCII.GetBytes(method);
                size = BitConverter.GetBytes(method.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(method_array);

                string pass = mainWindow.textBox_pass.Text;
                byte[] pass_array = Encoding.ASCII.GetBytes(pass);
                size = BitConverter.GetBytes(pass.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(pass_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadAuthResponse()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);

                    if ((identifiers)tip != identifiers.SSH_MSG_USERAUTH_SUCCESS)
                    {
                        // čitaj podatke primljene
                        byte[] infoSize_array = new byte[4];
                        infoSize_array = paket_decoded.Skip(6).Take(infoSize_array.Length).ToArray();
                        Array.Reverse(infoSize_array);
                        int infoSize = BitConverter.ToInt32(infoSize_array, 0);
                        string methods = Encoding.ASCII.GetString(paket_decoded.Skip(6 + infoSize_array.Length).Take(infoSize).ToArray());

                        // upozori
                        mainWindow.ShowDialogMsg("Neuspješna autentifikacija!\nPodržane metode:\n\n" + string.Join("\n", methods.Split(',')));
                        mainWindow.step -= 4;
                    }
                }

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelOpenPacket()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje CHANNEL_OPEN paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_OPEN);

                payload.Add(ident[0]);

                string req = "session";
                byte[] req_array = Encoding.ASCII.GetBytes(req);
                var size = BitConverter.GetBytes(req.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(req_array);

                int channel_num = 1;
                _localChannel = channel_num;
                var channel_num_array = BitConverter.GetBytes(channel_num);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(channel_num_array);

                payload.AddRange(channel_num_array);

                mainWindow.textBox_klijent_lokalni_kanal.Text = channel_num.ToString();

                int window_size;
                if (!int.TryParse(mainWindow.textBox_velicina_prozora.Text, out window_size))
                {
                    window_size = 240;
                }

                _windowSize = window_size;

                var window_size_array = BitConverter.GetBytes(window_size);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(window_size_array);

                payload.AddRange(window_size_array);

                // maksimalna veličina paketa je ista
                payload.AddRange(window_size_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadChannelOpenResponse()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi vlastiti kanala i provjeri ga
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] destination_channel_array = new byte[4];
                destination_channel_array = paket_decoded.Skip(6).Take(destination_channel_array.Length).ToArray();
                Array.Reverse(destination_channel_array);
                int destinationChannel = BitConverter.ToInt32(destination_channel_array, 0);

                paket_decoded = paket_decoded.Skip(6 + destination_channel_array.Length).ToArray();

                // pokupi broj udaljenog kanala
                byte[] remoteChannel_array = new byte[4];
                remoteChannel_array = paket_decoded.Take(4).ToArray();
                Array.Reverse(remoteChannel_array);
                _remoteChannel = BitConverter.ToInt32(remoteChannel_array, 0);

                paket_decoded = paket_decoded.Skip(4).ToArray();

                mainWindow.textBox_klijent_udaljeni_kanal.Text = _remoteChannel.ToString();

                // pokupi veličinu prozora
                byte[] windowSize_array = new byte[4];
                windowSize_array = paket_decoded.Take(4).ToArray();
                Array.Reverse(windowSize_array);
                _windowSize = BitConverter.ToInt32(windowSize_array, 0);

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelRequestPacket()
        {
            /*
            byte      SSH_MSG_CHANNEL_REQUEST
            uint32    recipient channel
            string    "exec"
            boolean   want reply
            string    command
            */

            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje CHANNEL_REQUEST paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_REQUEST);

                payload.Add(ident[0]);

                int channel_num = _remoteChannel;
                var channel_num_array = BitConverter.GetBytes(channel_num);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(channel_num_array);

                payload.AddRange(channel_num_array);

                string req = "exec";
                byte[] req_array = Encoding.ASCII.GetBytes(req);
                var size = BitConverter.GetBytes(req.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(req_array);

                byte reply = 0x01;

                payload.Add(reply);

                string command = mainWindow.textBox_naredba.Text;
                byte[] command_array = Encoding.ASCII.GetBytes(command);
                var command_array_size = BitConverter.GetBytes(command_array.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(command_array_size);

                payload.AddRange(command_array_size);
                payload.AddRange(command_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadChannelResponsePacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi vlastiti kanala i provjeri ga
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] destination_channel_array = new byte[4];
                destination_channel_array = paket_decoded.Skip(6).Take(destination_channel_array.Length).ToArray();
                Array.Reverse(destination_channel_array);
                int destinationChannel = BitConverter.ToInt32(destination_channel_array, 0);

                paket_decoded = paket_decoded.Skip(6 + destination_channel_array.Length).ToArray();

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadChannelDataPacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)

                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi vlastiti kanala i provjeri ga
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] destination_channel_array = new byte[4];
                destination_channel_array = paket_decoded.Skip(6).Take(destination_channel_array.Length).ToArray();
                Array.Reverse(destination_channel_array);
                int destinationChannel = BitConverter.ToInt32(destination_channel_array, 0);

                paket_decoded = paket_decoded.Skip(6 + destination_channel_array.Length).ToArray();

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }

                // pročitaj podatke primljene
                byte[] dataSize_array = new byte[4];
                dataSize_array = paket_decoded.Take(dataSize_array.Length).ToArray();
                Array.Reverse(dataSize_array);
                int dataSize = BitConverter.ToInt32(dataSize_array, 0);
                byte[] data = paket_decoded.Skip(dataSize_array.Length).Take(dataSize).ToArray();

                _dataReceived.AddRange(data);
                _lastDataSizeReceived = dataSize;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendWindowAdjustPacket()
        {
            /*
            byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
            uint32    recipient channel
            uint32    bytes to add
            */

            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje CHANNEL_WINDOW_ADJUST paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_WINDOW_ADJUST);

                payload.Add(ident[0]);

                int channel_num = _remoteChannel;
                var channel_num_array = BitConverter.GetBytes(channel_num);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(channel_num_array);

                payload.AddRange(channel_num_array);

                int bytesToAdd_num = _lastDataSizeReceived;
                var bytesToAdd_num_array = BitConverter.GetBytes(bytesToAdd_num);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(bytesToAdd_num_array);

                payload.AddRange(bytesToAdd_num_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ShowDataReceived()
        {
            mainWindow.textBox_rezultat.AppendText(Encoding.ASCII.GetString(_dataReceived.ToArray()));
            mainWindow.textBox_rezultat.AppendText("\n\n============================================================\n\n");
            _dataReceived.Clear();
        }

        public void ReadChannelEOFPacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi vlastiti kanala i provjeri ga
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] destination_channel_array = new byte[4];
                destination_channel_array = paket_decoded.Skip(6).Take(destination_channel_array.Length).ToArray();
                Array.Reverse(destination_channel_array);
                int destinationChannel = BitConverter.ToInt32(destination_channel_array, 0);

                paket_decoded = paket_decoded.Skip(6 + destination_channel_array.Length).ToArray();

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadChannelClosePacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, false });

                byte[] size = new byte[4];
                size = paket_decoded.Take(size.Length).ToArray();
                Array.Reverse(size);
                int packetSize = BitConverter.ToInt32(size, 0);

                int tip = Convert.ToInt32(paket_decoded[5]);
                string packetType = "undefined";
                if (Enum.IsDefined(typeof(identifiers), tip))
                {
                    packetType = Enum.GetName(typeof(identifiers), tip);
                }

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_client.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeySC });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = ("Krivi MAC kod!");
                    return;
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_client.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_client_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi vlastiti kanala i provjeri ga
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] destination_channel_array = new byte[4];
                destination_channel_array = paket_decoded.Skip(6).Take(destination_channel_array.Length).ToArray();
                Array.Reverse(destination_channel_array);
                int destinationChannel = BitConverter.ToInt32(destination_channel_array, 0);

                paket_decoded = paket_decoded.Skip(6 + destination_channel_array.Length).ToArray();

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelClosePacket()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Klijent šalje CHANNEL_CLOSE paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_CLOSE);

                payload.Add(ident[0]);

                int channel_num = _remoteChannel;
                var channel_num_array = BitConverter.GetBytes(channel_num);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(channel_num_array);

                payload.AddRange(channel_num_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeyCS });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, true });

                List<byte> wholePacket = new List<byte>();

                wholePacket.AddRange(paket_crypt);
                wholePacket.AddRange(mac);

                stream.SetLength(wholePacket.Count);

                stream.Write(wholePacket.ToArray(), 0, wholePacket.Count);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;
        }
    }
}