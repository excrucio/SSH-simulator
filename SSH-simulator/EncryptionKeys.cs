using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public class EncryptionKeys
    {
        public byte[] vectorCS { get; set; }
        public byte[] vectorSC { get; set; }
        public byte[] cryCS { get; set; }
        public byte[] crySC { get; set; }
        public byte[] MACKeyCS { get; set; }
        public byte[] MACKeySC { get; set; }
        public int MAClength { get; set; }
    }
}