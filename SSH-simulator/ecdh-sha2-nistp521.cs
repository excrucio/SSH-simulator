using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
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

        public static BigInteger CalculateSharedKey(BigInteger BIx, BigInteger BIy, ECPrivateKeyParameters privateKey)
        {
            IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
            aKeyAgree.Init(privateKey);

            X9ECParameters ecP = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ecSpec = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());

            FpCurve c = (FpCurve)ecSpec.Curve;

            ECFieldElement x = new FpFieldElement(c.Q, BIx);
            ECFieldElement y = new FpFieldElement(c.Q, BIy);
            ECPoint q = new FpPoint(ecP.Curve, x, y);

            ECPublicKeyParameters publicKey = new ECPublicKeyParameters("ECDH", q, SecObjectIdentifiers.SecP521r1);

            BigInteger k1 = aKeyAgree.CalculateAgreement(publicKey);

            return k1;
        }
    }
}