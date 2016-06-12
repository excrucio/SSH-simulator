using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSH_simulator
{
    public static class ecdh_sha2_nistp521
    {
        public static AsymmetricCipherKeyPair getKeyPair()
        {
            X9ECParameters ecP = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
            ECKeyPairGenerator g = new ECKeyPairGenerator();
            g.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));

            return g.GenerateKeyPair();
        }
    }
}