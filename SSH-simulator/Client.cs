using Org.BouncyCastle;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
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

        private AsymmetricCipherKeyPair DH_KeyPair;
        private ExchangeParameters ex_params = new ExchangeParameters();

        private EncryptionKeys keys = new EncryptionKeys();

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

        public bool SendIdentifierToServer()
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
                return false;
            }

            _clientIdent = mainWindow.textBox_clientIdent.Text;

            mainWindow.boolRetResult = true;
            mainWindow.textBox_info.Text = "Klijent poslao identifikacijski paket\n\n";
            return true;
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

                if ((bool)mainWindow.checkBox_ec_dh.IsChecked)
                {
                    DH_ALGORITHMS.Insert(0, "ec-dh");
                }

                if ((bool)mainWindow.checkBox_ssh_rsa.IsChecked)
                {
                    SIGNATURE_ALGORITHMS.Insert(0, "ssh-rsa");
                }

                if ((bool)mainWindow.checkBox_blowfish_ctr.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Insert(0, "blowfish-ctr");
                }

                if ((bool)mainWindow.checkBox_aes256_cbc.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Insert(0, "aes256-cbc");
                }

                if ((bool)mainWindow.checkBox_hmac_sha2.IsChecked)
                {
                    MAC_ALGORITHMS.Insert(0, "hmac-sha2");
                }

                if ((bool)mainWindow.checkBox_gost28147.IsChecked)
                {
                    MAC_ALGORITHMS.Insert(0, "gost28147");
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
                // TODO ostali dh klijent
                switch (algorithmsToUse.DH_algorithm)
                {
                    case "diffie-hellman-group1-sha1":
                        {
                            CalculateDH_g1();
                            break;
                        }

                    case "diffie-hellman-group14-sha1":
                        {
                            CalculateDH_g14();
                            break;
                        }
                }

                var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                var publicKey = DH_KeyPair.Public as DHPublicKeyParameters;

                ex_params.e = publicKey.Y;

                mainWindow.textBox_x.Text = privateKey.X.ToString();
                mainWindow.textBox_e.Text = publicKey.Y.ToString();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Could not generate keys!";
                return;
            }

            mainWindow.boolRetResult = true;
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

            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                Random rnd = new Random();

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

            if (ecdhPacket)
            {
                mainWindow.textBox_info.AppendText("Klijent poslao KEX_ECDH_INIT paket\n\n");
            }
            else
            {
                mainWindow.textBox_info.AppendText("Klijent poslao KEXDH_INIT paket\n\n");
            }
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

            // inače se radi o ECDH...
            // TODO ECDH klijent send
            return null;
        }

        public void ReadDHPacket()
        {
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                // koji dh paket?? "obični" ili ECDH?
                bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());
                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

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

                /*
                // provjeri da je K_S valjan
                // učitaj javni ključ i usporedi
                string serverCertPubKey = null;
                if (algorithmsToUse.SIGNATURE_algorithm == "ssh-rsa")
                {
                    // javni ključ
                    using (StreamReader txtStream = File.OpenText(@"ServerCert\public_server_keys"))
                    {
                        // prva je dss
                        string content = txtStream.ReadLine();
                        //druga je rsa
                        content = txtStream.ReadLine();
                        string rsaPub = content.Split(' ')[1];

                        serverCertPubKey = rsaPub;
                    }
                }
                else
                {
                    // inače je ssh-dss
                    // TODO server ssh-dss
                }

                if (Encoding.ASCII.GetString(K_S_array) != serverCertPubKey)
                {
                    mainWindow.boolRetResult = false;
                    mainWindow.retResult = "Krivi javni ključ servera!";
                    return;
                }
                */

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

                // izračunati hash
                byte[] hash = null;
                if (ecdhPacket)
                {
                    // TODO ecdh hash
                }
                else
                {
                    Debug.WriteLine("Sada klijent:");
                    hash = SSHHelper.ComputeSHA1Hash(_clientIdent, _serverIdent, _clientKEXINIT, _serverKEXINIT, K_S_param, ex_params.e, ex_params.f, ex_params.K);
                }

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

                // pokupi parametar e
                // paket - cijeli paket i sve
                // duljina paketa - bez sebe
                // uzmi samo dio s info: duljinaPaketa - duljinaDopune - 1

                int dopunaSize = Convert.ToInt32(paket[4]);

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
                mainWindow.label_cli_cry.Content = algorithmsToUse.ENCRYPTION_algorithm;
                mainWindow.label_cli_mac.Content = algorithmsToUse.MAC_algorithm;

                mainWindow.textBox_cli_K1.Text = ex_params.K.ToString();
                mainWindow.textBox_cli_H1.Text = BitConverter.ToString(Convert.FromBase64String(ex_params.H)).Replace("-", "").ToLower();

                mainWindow.textBox_info.AppendText("Klijent računa računa ključeve za enkripciju\n\n");

                keys = SSHHelper.GenerateEncryptionKeys(ex_params.K, ex_params.H, ex_params.H);

                mainWindow.textBox_cli_c_s.Text = BitConverter.ToString(Convert.FromBase64String(keys.vectoCS)).Replace("-", "").ToLower();
                mainWindow.textBox_cli_s_c.Text = BitConverter.ToString(Convert.FromBase64String(keys.vectorSC)).Replace("-", "").ToLower();
                mainWindow.textBox_cli_cry_c_s.Text = BitConverter.ToString(Convert.FromBase64String(keys.cryCS)).Replace("-", "").ToLower();
                mainWindow.textBox_cli_cry_s_c.Text = BitConverter.ToString(Convert.FromBase64String(keys.crySC)).Replace("-", "").ToLower();
                mainWindow.textBox_cli_MAC_c_s.Text = BitConverter.ToString(Convert.FromBase64String(keys.MACKeyCS)).Replace("-", "").ToLower();
                mainWindow.textBox_cli_MAC_s_c.Text = BitConverter.ToString(Convert.FromBase64String(keys.MACKeySC)).Replace("-", "").ToLower();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Klijent nije uspio izgenerirati ključeve!";
            }

            mainWindow.boolRetResult = true;
        }
    }
}