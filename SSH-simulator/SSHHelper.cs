using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public static class SSHHelper
    {
        public static byte[] CreatePacket(byte[] informations)
        {
            // duljina paketa[4] (bez sebe i MAC-a) | duljina dopune[1] | korisne informacije[duljina paketa - duljina dopune -1] | dopuna[od 4 do mod 8, max 255] | MAC

            // ispuna od 4 ili više baytova do mod 8
            // +4 zbog broja koji označava duljinu paketa i +1 za broj koji označava duljinu dopune, a ovdje ih trenutno nema...
            int fillNum = (informations.Length + 4 + 1) % 8;

            fillNum = 8 - fillNum;

            if (fillNum < 4)
            {
                fillNum += 8;
            }

            byte[] filler = new byte[fillNum];

            for (int i = 0; i < fillNum; i++)
            {
                filler[i] = 0x0;
            }

            List<byte> paket = new List<byte>();
            // +fillNum jer treba uzeti i duljinu dopune na kraju i +1 jer je toliko oznaka duljine dopune
            var size = BitConverter.GetBytes(informations.Length + fillNum + 1);
            // reverse zbog toga da ide iz little u big endian - ("normalni")
            Array.Reverse(size);

            var fillSize = BitConverter.GetBytes(fillNum);

            paket.AddRange(size);
            paket.Add(fillSize[0]);
            paket.AddRange(informations);
            paket.AddRange(filler);

            // MAC još nije dogovoren pa ga nema...
            return paket.ToArray();
        }

        public static string ispis(byte[] data)
        {
            string hex = BitConverter.ToString(data).Replace("-", " ");
            string text = Encoding.ASCII.GetString(data).Replace('\0', '.').Replace('\n', '.');

            int i = 0;
            int j = 0;
            int len = hex.Length;
            int len2 = text.Length;

            string output = "";
            try
            {
                while (i < len - 47)
                {
                    output += hex.Substring(i, 47) + "      " + text.Substring(j, 16) + "\n";

                    i += 47 + 1;
                    j += 16;
                }

                int fill = 0;
                if (len2 - j < 16)
                {
                    fill = 47 - (len2 - j) * 3 + 1;
                }

                output += hex.Substring(i, len - i) + "      " + text.Substring(j, len2 - j).PadLeft(fill + len2 - j) + "\n";
            }
            catch (Exception e)
            {
            }

            return output;
        }
    }
}