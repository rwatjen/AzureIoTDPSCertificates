using McMaster.Extensions.CommandLineUtils;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace RW.DPSCertificateTool
{
    [HelpOption]
    public class CreateVerificationCert
    {
        [Option("-s", LongName = "Subject", Description = "Verification key from portal - this will be used at the certificate subject and as part of the output filename.")]
        public string Subject { get; set; }

        [Option("-c", LongName = "CAPfxFile", Description = "The PFX file containing the root CA which will be used to issue the verification certificate.")]
        [FileExists]
        public string RootCaPfxFilename { get; set; }

        [Option("-p", LongName = "CAPassword", Description = "The password required to open the CA PFX file.")]
        public string RootCaPassword { get; set; }

        public int OnExecute()
        {
            var (caCert, caCertCollection) = CertificateUtil.LoadCertificateAndCollectionFromPfx(RootCaPfxFilename, RootCaPassword);
            var deviceCert = CertificateUtil.CreateAndSignCertificate(Subject, caCert);
            var deviceCertPublicKey = CertificateUtil.ExportCertificatePublicKey(deviceCert);
            var publicKeyBytes = deviceCert.Export(X509ContentType.Cert);
            File.WriteAllBytes($"{Subject}.cer", publicKeyBytes);
            return 0;
        }
    }
}