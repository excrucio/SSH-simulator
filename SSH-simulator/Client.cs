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

        private CryptoConfig crypto;

        public Client(MemoryStream ms, MainWindow mw)
        {
            mainWindow = mw;
            stream = ms;
            reader = new StreamReader(ms);
            writer = new StreamWriter(ms);
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
                mainWindow.retResult = "Could send to server!";
                return false;
            }

            mainWindow.boolRetResult = true;
            return true;
        }

        public void ReadServerId()
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

        public void SendKEXINIT()
        {
            List<byte> lista = new List<byte>();

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
            delimiter[0] = 0x0;
            delimiter[1] = 0x0;
            delimiter[2] = 0x0;

            lista.AddRange(payload);

            lista.AddRange(delimiter);
            lista.AddRange(dh);
            lista.AddRange(delimiter);
            lista.AddRange(dh);

            lista.AddRange(delimiter);
            lista.AddRange(sig);
            lista.AddRange(delimiter);
            lista.AddRange(sig);

            lista.AddRange(delimiter);
            lista.AddRange(cry);
            lista.AddRange(delimiter);
            lista.AddRange(cry);

            lista.AddRange(delimiter);
            lista.AddRange(mac);
            lista.AddRange(delimiter);
            lista.AddRange(mac);

            lista.AddRange(delimiter);
            lista.AddRange(compress);

            lista.AddRange(delimiter);
            lista.AddRange(compress);

            // TODO provjeri fillera!!
            // ispuna od 4 ili više baytova do mod 8
            // +1 zbog broja koji označava duljinu paketa, a ovdje ga trenutno nema...
            int fillNum = (lista.Count + 1) % 8;

            if (fillNum < 8 - 4)
            {
                fillNum += 8;
            }

            byte[] filler = new byte[fillNum];

            for (int i = 0; i < 8 - fillNum; i++)
            {
                filler[i] = 0x5;
            }

            lista.AddRange(filler);

            // sve to spojiti i to je korisni dio paketa

            byte[] all = lista.ToArray();

            // stvori paket
            byte[] paket = SSHHelper.CreatePacket(all, fillNum);

            stream.Write(paket, 0, paket.Length);
        }
    }
}