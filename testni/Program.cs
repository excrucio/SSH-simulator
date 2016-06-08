using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
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