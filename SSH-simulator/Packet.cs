using System.Collections.Generic;

namespace SSH_simulator
{
    public class AlgorithmsPacket
    {
        public List<string> DH_algorithms = new List<string>();
        public List<string> SIGNATURE_algorithms = new List<string>();
        public List<string> ENCRYPTION_algorithms = new List<string>();
        public List<string> MAC_algorithms = new List<string>();
    }
}