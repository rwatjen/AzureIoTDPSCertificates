using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace RW.DPSCertificateTool
{
    [HelpOption]
    public class CreateCertChain
    {
        [LegalFilePath]
        [Option("-s", LongName = "Subject", Description = "The generated root CA's certificate subject name. This will also be the base of the generated filenames.")]
        public string RootName { get; set; }

        [Option("-p", LongName = "Password", Description = "The password of the PFX file(s) that are output.")]
        public string Password { get; set; }

        [Range(0, 5)]
        [Option("-i", LongName = "Intermediates", Description = "The number of intermediate CAs to create in a chain.")]
        public int IntermediateCount { get; set; }

        public int OnExecute()
        {
            var rootCaCert = CertificateUtil.CreateCaCertificate(RootName, Password, null);
            CertificateUtil.SaveCertificateToPfxFile($"{RootName}.pfx", Password, rootCaCert, null, null);
            var rootPublicKey = CertificateUtil.ExportCertificatePublicKey(rootCaCert);
            var rootPublicKeyBytes = rootPublicKey.Export(X509ContentType.Cert);
            File.WriteAllBytes($"{RootName}.cer", rootPublicKeyBytes);
            var previousCaCert = rootCaCert;
            var chain = new X509Certificate2Collection();
            for (var i = 1; i <= IntermediateCount; i++)
            {
                var intermediateCert = CertificateUtil.CreateCaCertificate($"{RootName} - Intermediate {i}", Password, previousCaCert);
                var previousCaCertPublicKey = CertificateUtil.ExportCertificatePublicKey(previousCaCert);
                CertificateUtil.SaveCertificateToPfxFile($"Intermediate {i}.pfx", Password, intermediateCert, previousCaCertPublicKey, chain);
                chain.Add(previousCaCertPublicKey);
                previousCaCert = intermediateCert;
            }
            return 0;
        }
    }
}