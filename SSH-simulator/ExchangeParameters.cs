using Org.BouncyCastle.Math;

namespace SSH_simulator
{
    public class ExchangeParameters
    {
        public BigInteger e { get; set; }
        public BigInteger K { get; set; }
        public BigInteger p { get; set; }
    }
}