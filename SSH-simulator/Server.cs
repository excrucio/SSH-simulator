using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public class Server
    {
        public List<string> DH_ALGORITHMS = new List<string> { "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1" };
        public List<string> SIGNATURE_ALGORITHMS = new List<string> { "ssh-dss" };
        public List<string> ENCRYPTION_ALGORITHMS = new List<string> { "3des-cbc" };
        public List<string> MAC_ALGORITHMS = new List<string> { "hmac-sha1" };

        private const int SSH_DISCONNECT_MAC_ERROR = 5;

        private AsymmetricCipherKeyPair DH_KeyPair;

        private ExchangeParameters ex_params = new ExchangeParameters();

        private EncryptionKeys keys = new EncryptionKeys();
        private EncryptionAlgorithms encryptionAlgorithms = new EncryptionAlgorithms();

        private string _authResponse;
        private bool _userAuthenticated = false;
        private int _windowSize;
        private int _remoteChannel;
        private int _localChannel;

        private bool replyNeeded;
        private string commandToExec;
        private byte[] _dataForSending = null;

        private string _clientIdent;
        private string _serverIdent;
        private byte[] _clientKEXINIT;
        private byte[] _serverKEXINIT;

        private MemoryStream stream;
        private StreamReader reader;
        private StreamWriter writer;
        private MainWindow mainWindow;
        private AlgorithmsUsed algorithmsToUse = null;
        private AlgorithmsPacket algorithmsReceived;

        public Server(MemoryStream ms, MainWindow mw)
        {
            mainWindow = mw;
            stream = ms;
            reader = new StreamReader(ms);
            writer = new StreamWriter(ms);
        }

        public void SendIdentifierToClient()
        {
            try
            {
                writer.WriteLine(mainWindow.textBox_serverIdent.Text);
                writer.Flush();
            }
            catch (Exception e)
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Nije moguće kontaktirati klijenta!";
                return;
            }
            _serverIdent = mainWindow.textBox_serverIdent.Text;
            mainWindow.boolRetResult = true;
            mainWindow.textBox_info.AppendText("Server poslao identifikacijski paket\n\n");
            return;
        }

        public void ReadClientId()
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

                _clientIdent = line;
                mainWindow.textBox_server.Text = line;
                mainWindow.textBox_server_decoded.Text = line;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
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

                _clientKEXINIT = paket;

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

                if ((bool)mainWindow.checkBox_server_ec_dh.IsChecked)
                {
                    DH_ALGORITHMS.Insert(0, "ec-dh");
                }

                if ((bool)mainWindow.checkBox_server_ssh_rsa.IsChecked)
                {
                    SIGNATURE_ALGORITHMS.Insert(0, "ssh-rsa");
                }

                if ((bool)mainWindow.checkBox_server_blowfish_ctr.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Insert(0, "blowfish-ctr");
                }

                if ((bool)mainWindow.checkBox_server_aes256_cbc.IsChecked)
                {
                    ENCRYPTION_ALGORITHMS.Insert(0, "aes256-cbc");
                }

                if ((bool)mainWindow.checkBox_server_hmac_sha2.IsChecked)
                {
                    MAC_ALGORITHMS.Insert(0, "hmac-sha2");
                }

                if ((bool)mainWindow.checkBox_server_gost28147.IsChecked)
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

                _serverKEXINIT = paket;

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }

            mainWindow.boolRetResult = true;

            mainWindow.textBox_info.AppendText("Server poslao KEXINIT paket\n\n");
        }

        public void SetAlgorithms()
        {
            try
            {
                AlgorithmsUsed usedAl = SSHHelper.GetAlgorithmsForServerToUse(DH_ALGORITHMS, SIGNATURE_ALGORITHMS, ENCRYPTION_ALGORITHMS, MAC_ALGORITHMS, algorithmsReceived);

                algorithmsToUse = usedAl;

                mainWindow.textBox_info.AppendText("Server utvrđuje koje algoritme da koristi na osnovu primljenih paketa\n\n");

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
                mainWindow.textBox_info.AppendText("Server računa parametre za Diffie-Hellman razmjenu\n\n");

                // what dh to calculate
                switch (algorithmsToUse.DH_algorithm)
                {
                    case "ecdh-sha2-nistp521":
                        {
                            Calculate_ecdh_sha2_nistp521();
                            var senderPrivate = ((ECPrivateKeyParameters)DH_KeyPair.Private).D.ToByteArrayUnsigned();
                            var senderPublic = ((ECPublicKeyParameters)DH_KeyPair.Public).Q.GetEncoded();
                            mainWindow.textBox_y.Text = BitConverter.ToString(senderPrivate).Replace("-", "").ToLower();
                            mainWindow.textBox_f.Text = BitConverter.ToString(senderPublic).Replace("-", "").ToLower();

                            mainWindow.label_ser_privatni_kljuc_DH.Content = "DH privatni ključ";
                            mainWindow.label_ser_javni_kljuc.Content = "DH javni ključ";
                            break;
                        }
                    case "diffie-hellman-group1-sha1":
                        {
                            CalculateDH_g1();
                            var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                            var publicKey = DH_KeyPair.Public as DHPublicKeyParameters;

                            ex_params.f = publicKey.Y;

                            mainWindow.textBox_y.Text = privateKey.X.ToString();
                            mainWindow.textBox_f.Text = publicKey.Y.ToString();
                            break;
                        }

                    case "diffie-hellman-group14-sha1":
                        {
                            CalculateDH_g14();
                            var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                            var publicKey = DH_KeyPair.Public as DHPublicKeyParameters;

                            ex_params.f = publicKey.Y;

                            mainWindow.textBox_y.Text = privateKey.X.ToString();
                            mainWindow.textBox_f.Text = publicKey.Y.ToString();
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
            var senderPrivate = ((ECPrivateKeyParameters)keyPair.Private).D.ToString();
            var senderPublic = ((ECPublicKeyParameters)keyPair.Public).Q.ToString();

            DH_KeyPair = keyPair;
        }

        private void CalculateDH_g1()
        {
            BigInteger p = new BigInteger(DHg1.p_hex, 16);
            BigInteger g = new BigInteger(DHg1.g_hex, 16);

            var kp = GetDHKeyPair(p, g);

            ex_params.p = p;

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
            mainWindow.textBox_ser_mod_p.Text = p.ToString();
            mainWindow.textBox_ser_g.Text = g.ToString();

            DHParameters importedParameters = new DHParameters(p, g);

            var keyGen = GeneratorUtilities.GetKeyPairGenerator("DH");

            KeyGenerationParameters kgp = new DHKeyGenerationParameters(new SecureRandom(), importedParameters);
            keyGen.Init(kgp);

            AsymmetricCipherKeyPair KeyPair = keyGen.GenerateKeyPair();

            return KeyPair;
        }

        public void ReadDHPacket()
        {
            if (algorithmsToUse.DH_algorithm == "ecdh-sha2-nistp521")
            {
                ReadECDHPacket();
                return;
            }

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());

                // pokupi parametar e
                // paket - cijeli paket i sve
                // duljina paketa - bez sebe
                // uzmi samo dio s info: duljinaPaketa - duljinaDopune - 1

                int dopunaSize = Convert.ToInt32(paket[4]);

                // 6 jer je 4 size, 1 dopuna size, 1 paket identifier
                var e_size_array = paket.Skip(6).Take(4).ToArray();

                Array.Reverse(e_size_array);
                int e_size = BitConverter.ToInt32(e_size_array, 0);
                var e_array = paket.Skip(6 + 4).Take(e_size).ToArray();
                // 1 je zato jer se koristi unsigned array...
                // nema logike, ali jbg... tako je...
                var e_param = new BigInteger(1, e_array);

                var privateKey = DH_KeyPair.Private as DHPrivateKeyParameters;
                // K = e^y mod p
                var K = e_param.ModPow(privateKey.X, ex_params.p);

                ex_params.K = K;
                ex_params.e = e_param;

                mainWindow.textBox_ser_K.Text = ex_params.K.ToString();

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        private void ReadECDHPacket()
        {
            //TODO čitaj ECDH paket
        }

        public void SendDHPacket()
        {
            // radi se od kexdh_replay

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
                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEX_ECDH_REPLY);
                }
                else
                {
                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_KEXDH_REPLY);
                }

                payload.Add(ident[0]);

                // pokupi privatni ključ i javni certifikata
                string serverCertPubKey = null;
                AsymmetricCipherKeyPair rsaKeys = null;
                if (algorithmsToUse.SIGNATURE_algorithm == "ssh-rsa")
                {
                    // privatni ključ
                    using (StreamReader txtStream = File.OpenText(@"ServerCert\server_rsa.pem"))
                    {
                        PemReader reader = new PemReader(txtStream);
                        rsaKeys = (AsymmetricCipherKeyPair)reader.ReadObject();
                    }

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

                // izračunati i dodati stvari u paket

                // dodati javi ključ servera (javni ključ certifikata)
                var size_certKey = BitConverter.GetBytes(serverCertPubKey.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size_certKey);
                payload.AddRange(size_certKey);
                payload.AddRange(Encoding.ASCII.GetBytes(serverCertPubKey));

                // dodati javi ključ od DH (f parametar)
                var pub = DH_KeyPair.Public as DHPublicKeyParameters;
                var publicKey = pub.Y.ToByteArray();
                var size_pubKey = BitConverter.GetBytes(publicKey.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size_pubKey);
                payload.AddRange(size_pubKey);
                payload.AddRange(publicKey);

                // izračunati hash
                byte[] hash = null;
                if (ecdhPacket)
                {
                    // TODO ecdh hash
                }
                else
                {
                    hash = SSHHelper.ComputeSHA1Hash(_clientIdent, _serverIdent, _clientKEXINIT, _serverKEXINIT, serverCertPubKey, ex_params.e, ex_params.f, ex_params.K);
                }

                string hashBase64 = Convert.ToBase64String(hash);

                ex_params.H = hashBase64;

                mainWindow.textBox_ser_H.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();

                // potpisati hash i dodati potpis
                byte[] signature = null;
                // rsa
                if (algorithmsToUse.SIGNATURE_algorithm == "ssh-rsa")
                {
                    var encryptEngine = new Pkcs1Encoding(new RsaEngine());

                    encryptEngine.Init(true, rsaKeys.Private);
                    var crypt = encryptEngine.ProcessBlock(hash, 0, hash.Length);
                    var encrypted = Convert.ToBase64String(crypt);

                    mainWindow.textBox_sig_H.Text = BitConverter.ToString(crypt).Replace("-", "").ToLower();

                    signature = Encoding.ASCII.GetBytes(encrypted);
                }
                // dss
                else
                {
                    // TODO server ssh-dss
                }

                var size_sig = BitConverter.GetBytes(signature.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size_sig);
                payload.AddRange(size_sig);
                payload.AddRange(signature);

                byte[] all = payload.ToArray();

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
                mainWindow.textBox_info.AppendText("Server poslao KEX_ECDH_REPLY paket\n\n");
            }
            else
            {
                mainWindow.textBox_info.AppendText("Server poslao KEXDH_REPLY paket\n\n");
            }
        }

        private void SendECDHPacket()
        {
            //TODO šalji ECDH paket
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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());

                // pokupi parametar e
                // paket - cijeli paket i sve
                // duljina paketa - bez sebe
                // uzmi samo dio s info: duljinaPaketa - duljinaDopune - 1

                int dopunaSize = Convert.ToInt32(paket[4]);

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
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

                mainWindow.textBox_info.AppendText("Server šalje NEWKEYS paket\n\n");

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
                return;
            }
        }

        public void GenerateEncryptionKeys()
        {
            try
            {
                mainWindow.label_ser_cry.Content = algorithmsToUse.ENCRYPTION_algorithm;
                mainWindow.label_ser_mac.Content = algorithmsToUse.MAC_algorithm;

                mainWindow.textBox_ser_K1.Text = ex_params.K.ToString();
                mainWindow.textBox_ser_H1.Text = BitConverter.ToString(Convert.FromBase64String(ex_params.H)).Replace("-", "").ToLower();

                mainWindow.textBox_info.AppendText("Server računa ključeve za enkripciju\n\n");

                keys = SSHHelper.GenerateEncryptionKeys(algorithmsToUse.ENCRYPTION_algorithm, algorithmsToUse.MAC_algorithm, ref encryptionAlgorithms, ex_params.K, ex_params.H, ex_params.H);

                mainWindow.textBox_ser_c_s.Text = BitConverter.ToString(keys.vectorCS).Replace("-", "").ToLower();
                mainWindow.textBox_ser_s_c.Text = BitConverter.ToString(keys.vectorSC).Replace("-", "").ToLower();
                mainWindow.textBox_ser_cry_c_s.Text = BitConverter.ToString(keys.cryCS).Replace("-", "").ToLower();
                mainWindow.textBox_ser_cry_s_c.Text = BitConverter.ToString(keys.crySC).Replace("-", "").ToLower();
                mainWindow.textBox_ser_MAC_c_s.Text = BitConverter.ToString(keys.MACKeyCS).Replace("-", "").ToLower();
                mainWindow.textBox_ser_MAC_s_c.Text = BitConverter.ToString(keys.MACKeySC).Replace("-", "").ToLower();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Server nije uspio izgenerirati ključeve!";
            }

            mainWindow.boolRetResult = true;
        }

        public void ReadServiceRequestPacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                // pokupi vrstu autentifikacije
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa + 4 veličina stringa
                byte[] infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Skip(6).Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                int infoSize = BitConverter.ToInt32(infoSize_array, 0);
                _authResponse = Encoding.ASCII.GetString(paket_decoded.Skip(6 + infoSize_array.Length).Take(infoSize).ToArray());

                string output = SSHHelper.ispis(paket_decoded);

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        private void SendServiceDisconnectPacket()
        {
            try
            {
                mainWindow.textBox_info.AppendText("Server šalje SERVICE_DISCONNECT paket\n\n");
                mainWindow.button_next.IsEnabled = false;
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "MAC se ne podudara!\nPrekid veze!";

                stream.Seek(0, SeekOrigin.Begin);

                // kao, šalje paket....

                stream.Seek(0, SeekOrigin.Begin);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješano slanje paketa!";
                return;
            }
        }

        public void SendServiceAcceptPacket()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Server šalje SERVICE_ACCEPT paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_SERVICE_ACCEPT);

                payload.Add(ident[0]);

                string req = _authResponse;
                byte[] req_array = Encoding.ASCII.GetBytes(req);
                var size = BitConverter.GetBytes(req.Length);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size);

                payload.AddRange(size);
                payload.AddRange(req_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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

        public void ReadAuth()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi username
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa + 4 veličina stringa
                byte[] infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Skip(6).Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                int infoSize = BitConverter.ToInt32(infoSize_array, 0);
                string username = Encoding.UTF8.GetString(paket_decoded.Skip(6 + infoSize_array.Length).Take(infoSize).ToArray());

                // "pomakni" paket
                paket_decoded = paket_decoded.Skip(6 + infoSize + infoSize_array.Length).ToArray();

                // preskoči "service" i "method" dio jer znam da je user/pass
                infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                infoSize = BitConverter.ToInt32(infoSize_array, 0);
                // "pomakni" paket
                paket_decoded = paket_decoded.Skip(infoSize + infoSize_array.Length).ToArray();

                infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                infoSize = BitConverter.ToInt32(infoSize_array, 0);
                // "pomakni" paket
                paket_decoded = paket_decoded.Skip(infoSize + infoSize_array.Length).ToArray();

                // pokupi šifru
                infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                infoSize = BitConverter.ToInt32(infoSize_array, 0);
                string pass = Encoding.ASCII.GetString(paket_decoded.Skip(infoSize_array.Length).Take(infoSize).ToArray());
                // "pomakni" paket
                paket_decoded = paket_decoded.Skip(infoSize + infoSize_array.Length).ToArray();

                //učitaj podatke o korisnicima iz baze (txt dokumenta)
                string baza = "UsersDB.txt";

                if (mainWindow.textBox_baza_korisnika.Text != "")
                {
                    baza = mainWindow.textBox_baza_korisnika.Text;
                }

                if (!File.Exists(baza))
                {
                    mainWindow.boolRetResult = true;
                    mainWindow.ShowDialogMsg("Server ne može otvoriti bazu korisnika!");
                    mainWindow.step -= 2;
                    return;
                }

                List<string> logins = File.ReadAllLines(baza).ToList();
                bool authenticated = false;
                foreach (string login in logins)
                {
                    if (!login.Contains(";"))
                    {
                        continue;
                    }

                    string u = login.Split(';')[0];
                    string p = login.Split(';')[1];

                    if (u == username && p == pass)
                    {
                        authenticated = true;
                        break;
                    }
                }

                _userAuthenticated = authenticated;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendAuthResponse()
        {
            // napravi paket
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;
                if (_userAuthenticated)
                {
                    mainWindow.textBox_info.AppendText("Server šalje USERAUTH_SUCCESS paket\n\n");

                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_USERAUTH_SUCCESS);
                    payload.Add(ident[0]);
                }
                else
                {
                    mainWindow.textBox_info.AppendText("Server šalje USERAUTH_FAILURE paket\n\n");

                    ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_USERAUTH_FAILURE);
                    payload.Add(ident[0]);

                    string req = "password";
                    byte[] req_array = Encoding.ASCII.GetBytes(req);
                    var size = BitConverter.GetBytes(req.Length);
                    // reverse zbog toga da ide iz little u big endian - ("normalni")
                    Array.Reverse(size);

                    payload.AddRange(size);
                    payload.AddRange(req_array);
                }

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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

        public void ReadChannelOpenPacket()
        {
            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi "session" - znam da je to pa preskačem
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa + 4 veličina stringa
                byte[] infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Skip(6).Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                int infoSize = BitConverter.ToInt32(infoSize_array, 0);

                paket_decoded = paket_decoded.Skip(6 + infoSize + infoSize_array.Length).ToArray();

                // pokupi broj udaljenog kanala
                byte[] remoteChannel_array = new byte[4];
                remoteChannel_array = paket_decoded.Take(4).ToArray();
                Array.Reverse(remoteChannel_array);
                _remoteChannel = BitConverter.ToInt32(remoteChannel_array, 0);

                paket_decoded = paket_decoded.Skip(4).ToArray();

                mainWindow.textBox_server_udaljeni_kanal.Text = _remoteChannel.ToString();

                _localChannel = _remoteChannel + 1;

                mainWindow.textBox_server_lokalni_kanal.Text = _localChannel.ToString();

                // pokupi veličinu prozora
                byte[] windowSize_array = new byte[4];
                windowSize_array = paket_decoded.Take(4).ToArray();
                Array.Reverse(windowSize_array);
                _windowSize = BitConverter.ToInt32(windowSize_array, 0);
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelOpenResponse()
        {
            // napravi paket
            try
            {
                mainWindow.textBox_info.AppendText("Server šalje CHANNEL_OPEN_CONFIRMATION paket\n\n");

                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);

                payload.Add(ident[0]);

                var remote_channel_array = BitConverter.GetBytes(_remoteChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(remote_channel_array);

                payload.AddRange(remote_channel_array);

                var local_channel_array = BitConverter.GetBytes(_localChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(local_channel_array);

                payload.AddRange(local_channel_array);

                var window_size_array = BitConverter.GetBytes(_windowSize);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(window_size_array);

                payload.AddRange(window_size_array);

                // maksimalna veličina paketa je ista
                payload.AddRange(window_size_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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

        public void ReadChannelRequestPacket()
        {
            /*
            byte      SSH_MSG_CHANNEL_REQUEST
            uint32    recipient channel
            string    "exec"
            boolean   want reply
            string    command
            */

            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi kanal
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] channel_array = new byte[4];
                channel_array = paket_decoded.Skip(6).Take(channel_array.Length).ToArray();
                Array.Reverse(channel_array);
                int destinationChannel = BitConverter.ToInt32(channel_array, 0);

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }

                paket_decoded = paket_decoded.Skip(6 + channel_array.Length).ToArray();

                // pokupi "exec" - znam da je to pa preskačem
                byte[] infoSize_array = new byte[4];
                infoSize_array = paket_decoded.Take(infoSize_array.Length).ToArray();
                Array.Reverse(infoSize_array);
                int infoSize = BitConverter.ToInt32(infoSize_array, 0);

                paket_decoded = paket_decoded.Skip(infoSize + infoSize_array.Length).ToArray();

                // pokupi treba li reply
                byte[] reply_array;
                reply_array = paket_decoded.Take(1).ToArray();
                bool reply = BitConverter.ToBoolean(reply_array, 0);

                this.replyNeeded = reply;

                paket_decoded = paket_decoded.Skip(1).ToArray();

                // pokupi naredbu
                byte[] command_array = new byte[4];
                command_array = paket_decoded.Take(command_array.Length).ToArray();
                Array.Reverse(command_array);
                int commandSize = BitConverter.ToInt32(command_array, 0);

                string command = Encoding.ASCII.GetString(paket_decoded.Skip(command_array.Length).Take(commandSize).ToArray());

                this.commandToExec = command;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelRespondPacket()
        {
            // napravi paket
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;

                mainWindow.textBox_info.AppendText("Server šalje CHANNEL_SUCCESS paket\n\n");

                ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_SUCCESS);
                payload.Add(ident[0]);

                var remote_channel_array = BitConverter.GetBytes(_remoteChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(remote_channel_array);

                payload.AddRange(remote_channel_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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

        public void ExecuteCommand()
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.CreateNoWindow = true;
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C " + commandToExec;
            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;

            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();

            _dataForSending = Encoding.ASCII.GetBytes(output);
        }

        public bool SendChannelDataPackets()
        {
            if (!replyNeeded)
            {
                _dataForSending = new byte[0];
                return false;
            }

            // inače šalji paket dok ih ima

            if (_dataForSending.Length <= 0)
            {
                return false;
            }

            /*
            byte      SSH_MSG_CHANNEL_DATA
            uint32    recipient channel
            string    data
            */

            // napravi paket
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;

                mainWindow.textBox_info.AppendText("Server šalje CHANNEL_DATA paket\n\n");

                ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_DATA);
                payload.Add(ident[0]);

                var remote_channel_array = BitConverter.GetBytes(_remoteChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(remote_channel_array);

                payload.AddRange(remote_channel_array);

                // podaci veličine windowSize
                byte[] data_array = _dataForSending;
                int size = Math.Min(_windowSize, data_array.Length);

                var size_array = BitConverter.GetBytes(size);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(size_array);

                payload.AddRange(size_array);

                byte[] toSend = data_array.Take(size).ToArray();

                payload.AddRange(toSend);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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
                _dataForSending = null;
                return true;
            }

            mainWindow.boolRetResult = true;

            // možda ima još
            return true;
        }

        public void ReadWindowAdjustPacket()
        {
            /*
            byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
            uint32    recipient channel
            uint32    bytes to add
            */

            // čitaj i provjeri MAC
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket = new byte[stream.Length - keys.MAClength];

                stream.Read(paket, 0, (int)stream.Length - keys.MAClength);

                stream.Seek(0, SeekOrigin.Begin);

                byte[] paket_decoded;
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi kanal
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] channel_array = new byte[4];
                channel_array = paket_decoded.Skip(6).Take(channel_array.Length).ToArray();
                Array.Reverse(channel_array);
                int destinationChannel = BitConverter.ToInt32(channel_array, 0);

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }

                paket_decoded = paket_decoded.Skip(6 + channel_array.Length).ToArray();

                byte[] bytes_array = new byte[4];
                bytes_array = paket_decoded.Take(bytes_array.Length).ToArray();
                Array.Reverse(bytes_array);
                int bytes = BitConverter.ToInt32(bytes_array, 0);

                // "pomakni" podatke
                _dataForSending = _dataForSending.Skip(bytes).ToArray();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }

        public void SendChannelEOFPacket()
        {
            // napravi paket
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;

                mainWindow.textBox_info.AppendText("Server šalje CHANNEL_EOF paket\n\n");

                ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_EOF);
                payload.Add(ident[0]);

                var remote_channel_array = BitConverter.GetBytes(_remoteChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(remote_channel_array);

                payload.AddRange(remote_channel_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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

        public void SendChannelClosePacket()
        {
            // napravi paket
            try
            {
                stream.Seek(0, SeekOrigin.Begin);

                List<byte> payload = new List<byte>();

                // identifikator paketa
                byte[] ident;

                mainWindow.textBox_info.AppendText("Server šalje CHANNEL_CLOSE paket\n\n");

                ident = BitConverter.GetBytes((int)identifiers.SSH_MSG_CHANNEL_CLOSE);
                payload.Add(ident[0]);

                var remote_channel_array = BitConverter.GetBytes(_remoteChannel);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(remote_channel_array);

                payload.AddRange(remote_channel_array);

                byte[] all = payload.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket, keys.MACKeySC });

                byte[] paket_crypt = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.crySC, keys.vectorSC, true });

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
                paket_decoded = (byte[])encryptionAlgorithms.encryption.Invoke(null, new object[] { paket, keys.cryCS, keys.vectorCS, false });

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

                mainWindow.textBox_server.AppendText("\n\n\n" + output);

                // MAC dio
                byte[] mac = (byte[])encryptionAlgorithms.MAC.Invoke(null, new object[] { paket_decoded, keys.MACKeyCS });

                byte[] macReceived = new byte[keys.MAClength];
                stream.Seek(paket.Length, SeekOrigin.Begin);

                stream.Read(macReceived, 0, macReceived.Length);
                string mC = BitConverter.ToString(mac);
                string mR = BitConverter.ToString(macReceived);
                if (mC != mR)
                {
                    //problem
                    SendServiceDisconnectPacket();
                }

                string macHex = SSHHelper.ispis(macReceived);
                mainWindow.textBox_server.AppendText("MAC:\n" + macHex);

                string outputDecoded = SSHHelper.ispis(paket_decoded.Skip(5).ToArray());

                mainWindow.textBox_server_decoded.AppendText("\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded);

                // pokupi kanal
                // 6 = zbog 4 veličine, 1 veličina dopune, 1 vrsta paketa
                byte[] channel_array = new byte[4];
                channel_array = paket_decoded.Skip(6).Take(channel_array.Length).ToArray();
                Array.Reverse(channel_array);
                int destinationChannel = BitConverter.ToInt32(channel_array, 0);

                if (destinationChannel != _localChannel)
                {
                    //problem
                    mainWindow.retResult = "Krivi broj odredišnog kanala!";
                    mainWindow.boolRetResult = false;
                    return;
                }

                paket_decoded = paket_decoded.Skip(6 + channel_array.Length).ToArray();
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
                return;
            }

            mainWindow.boolRetResult = true;
        }
    }
}