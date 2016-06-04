using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public static class SSHHelper
    {
        public static byte[] CreatePacket(byte[] informations, int fillNum)
        {
            // duljina paketa[4] (bez sebe i MAC-a) | duljina dopune[1] | korisne informacije[duljina paketa - duljina dopune -1] | dopuna[od 4 do mod 8, max 255] | MAC

            List<byte> paket = new List<byte>();
            // reverse zbog toga da ide iz little u big endian ("normalni")
            var size = BitConverter.GetBytes(informations.Length);
            Array.Reverse(size);

            var fillSize = BitConverter.GetBytes(fillNum);

            paket.AddRange(size);
            paket.Add(fillSize[0]);
            paket.AddRange(informations);

            // MAC još nije dogovoren...
            return paket.ToArray();
        }

        public static string ispis(byte[] data)
        {
            string hex = BitConverter.ToString(data).Replace("-", " ");
            string text = Encoding.ASCII.GetString(data).Replace('\0', '_').Replace('\n', '_');

            int i = 0;
            int j = 0;
            int len = hex.Length;
            int len2 = text.Length;
            string output = "";
            try
            {
                while (i < len - 47)
                {
                    output += hex.Substring(i, 47) + "        " + text.Substring(j, 16) + "\n";

                    i += 47 + 1;
                    j += 16;
                }

                output += hex.Substring(i, len - i) + "       " + text.Substring(j, len2 - j).PadLeft(47 - len + i + len2 - j + 13) + "\n";
            }
            catch (Exception e)
            {
            }

            return output;
        }
    }
}