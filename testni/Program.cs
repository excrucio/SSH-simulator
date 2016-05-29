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
            Console.WriteLine("Server start call!");
            StartServer();

            Thread.Sleep(1500);
            Console.WriteLine("Klijent start call!");
            StartKlijent("pa kako je, ša ima?");

            Console.ReadKey();
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