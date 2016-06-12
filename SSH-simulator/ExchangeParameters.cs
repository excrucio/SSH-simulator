using Org.BouncyCastle.Math;

namespace SSH_simulator
{
    public class ExchangeParameters
    {
        public BigInteger x { get; set; }
        public BigInteger y { get; set; }

        public BigInteger x_c { get; set; }
        public BigInteger y_c { get; set; }
        public BigInteger e { get; set; }
        public BigInteger f { get; set; }
        public BigInteger K { get; set; }
        public BigInteger p { get; set; }
        public string H { get; set; }
    }
}