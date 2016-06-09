using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
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

        private AsymmetricCipherKeyPair DH_KeyPair;

        private ExchangeParameters ex_params = new ExchangeParameters();

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

        public bool SendIdentifierToClient()
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
                return false;
            }
            _serverIdent = mainWindow.textBox_serverIdent.Text;
            mainWindow.boolRetResult = true;
            mainWindow.textBox_info.AppendText("Server poslao identifikacijski paket\n\n");
            return true;
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
                // TODO ostali dh server
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

                ex_params.f = publicKey.Y;

                mainWindow.textBox_y.Text = privateKey.X.ToString();
                mainWindow.textBox_f.Text = publicKey.Y.ToString();
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
                var e_param = new BigInteger(e_array);

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

        public void SendDHPacket()
        {
            // radi se od kexdh_replay

            // koji dh paket?? "obični" ili ECDH?
            bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");

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
                string serverCertPrivKey = null;
                AsymmetricCipherKeyPair rsaKeys = null;
                if (algorithmsToUse.SIGNATURE_algorithm == "ssh-rsa")
                {
                    // privatni ključ
                    using (StreamReader txtStream = File.OpenText(@"ServerCert\server_rsa.pem"))
                    {
                        PemReader reader = new PemReader(txtStream);
                        rsaKeys = (AsymmetricCipherKeyPair)reader.ReadObject();
                        serverCertPrivKey = txtStream.ReadToEnd();
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

                mainWindow.textBox_ser_H.Text = Encoding.ASCII.GetString(hash);

                // potpisati hash i dodati potpis
                byte[] signature = null;
                // rsa
                if (algorithmsToUse.SIGNATURE_algorithm == "ssh-rsa")
                {
                    var encryptEngine = new Pkcs1Encoding(new RsaEngine());

                    encryptEngine.Init(true, rsaKeys.Private);

                    var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(hash, 0, hash.Length));

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

        private byte[] GetKEXDHKEysPayload()
        {
            bool ecdhPacket = algorithmsToUse.DH_algorithm.StartsWith("ecdh");
            if (!ecdhPacket)
            {
                var pub = DH_KeyPair.Public as DHPublicKeyParameters;
                var publicKey = pub.Y.ToByteArray();

                return publicKey;
            }

            // inače se radi o ECDH...
            // TODO ECDH klijent send
            return null;
        }
    }
}