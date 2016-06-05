using Renci.SshNet;
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
    public class Client
    {
        public static List<string> DH_ALGORITHMS = new List<string> { "diffie-hellman-group1-sha1", "diffie-helmann-group14-sha1" };
        public static List<string> SIGNATURE_ALGORITHMS = new List<string> { "ssh-dss" };
        public static List<string> ENCRYPTION_ALGORITHMS = new List<string> { "3des-cbc" };
        public static List<string> MAC_ALGORITHMS = new List<string> { "hmac-sha1" };

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

                mainWindow.textBox_client.Text = line;
                mainWindow.textBox_client_decoded.Text = line;
            }
            catch
            {
                mainWindow.boolRetResult = false;
                mainWindow.retResult = "Neuspješan primitak paketa!";
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

                // delimiteri su: 0E (14), 0F (15), 25 (35), 3D (61), 5B (91)

                List<byte> lista = new List<byte>();

                lista.AddRange(payload);

                delimiter = BitConverter.GetBytes(14);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(dh);

                delimiter = BitConverter.GetBytes(15);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(sig);

                delimiter = BitConverter.GetBytes(35);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(cry);
                lista.AddRange(delimiter);
                lista.AddRange(cry);

                delimiter = BitConverter.GetBytes(61);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(mac);
                lista.AddRange(delimiter);
                lista.AddRange(mac);

                delimiter = BitConverter.GetBytes(91);
                // reverse zbog toga da ide iz little u big endian - ("normalni")
                Array.Reverse(delimiter);

                lista.AddRange(delimiter);
                lista.AddRange(compress);
                lista.AddRange(delimiter);
                lista.AddRange(compress);

                // sve to spojiti i to je korisni dio paketa

                byte[] all = lista.ToArray();

                // stvori paket
                byte[] paket = SSHHelper.CreatePacket(all);

                stream.Write(paket, 0, paket.Length);
            }
            catch
            {
                mainWindow.retResult = "Paket nije moguće poslati!";
                mainWindow.boolRetResult = false;
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
            }

            mainWindow.boolRetResult = true;
        }

        public void SetAlgorithms()
        {
            try
            {
                AlgorithmsUsed usedAl = SSHHelper.GetAlgorithmsForClientToUse(DH_ALGORITHMS, SIGNATURE_ALGORITHMS, ENCRYPTION_ALGORITHMS, MAC_ALGORITHMS, algorithmsReceived);

                algorithmsToUse = usedAl;

                mainWindow.textBox_info.AppendText("Klijent i server utvrđuju koje algoritme da koriste na osnovu primljenih paketa\n\n");

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
            }

            mainWindow.boolRetResult = true;
        }
    }
}