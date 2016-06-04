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
        public static List<string> DH_ALGORITHMS = new List<string> { "diffie-hellman-group1-sha1", "diffie-helmann-group14-sha1" };
        public static List<string> SIGNATURE_ALGORITHMS = new List<string> { "ssh-dss" };
        public static List<string> ENCRYPTION_ALGORITHMS = new List<string> { "3des-cbc" };
        public static List<string> MAC_ALGORITHMS = new List<string> { "hmac-sha1" };

        private MemoryStream stream;
        private StreamReader reader;
        private StreamWriter writer;
        private MainWindow mainWindow;

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
                mainWindow.retResult = "Could send to client!";
                return false;
            }

            mainWindow.boolRetResult = true;
            return true;
        }

        public void ReadClientId()
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

            mainWindow.textBox_server.Text = line;
            mainWindow.textBox_server_decoded.Text = line;
        }

        public void ReadKEXINIT()
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

            mainWindow.textBox_server.Text += "\n\n\n" + output;

            string outputDecoded = SSHHelper.ispis(paket.Skip(5).ToArray());

            mainWindow.textBox_server_decoded.Text += "\n\n\nVrsta paketa: " + packetType + " (" + tip + ")\n" + outputDecoded;
        }
    }
}