using System;
using System.Collections.Generic;
using System.Reflection;

namespace SSH_simulator
{
    public class EncryptionAlgorithms
    {
        public MethodInfo encryption { get; set; }
        public MethodInfo MAC { get; set; }
    }
}