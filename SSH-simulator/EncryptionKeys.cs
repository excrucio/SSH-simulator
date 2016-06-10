using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public class EncryptionKeys
    {
        public string vectoCS { get; set; }
        public string vectorSC { get; set; }
        public string cryCS { get; set; }
        public string crySC { get; set; }
        public string MACKeyCS { get; set; }
        public string MACKeySC { get; set; }
    }
}