using McMaster.Extensions.CommandLineUtils;
using System;
using System.ComponentModel.DataAnnotations;

namespace RW.DPSCertificateTool
{
    [HelpOption]
    public class CreateDeviceCert
    {
        [Required]
        [Option("-s", LongName ="Subject", Description = "The subject name of the new certifcate. The generated PFX file will also be named after the subject.")]
        public string SubjectName { get; set; }

        [Required]
        [Option("-p", LongName = "Password", Description = "Password of the generated PFX file.")]
        public string NewCertPassword { get; set; }

        [Required]
        [Option("-c", LongName = "CAPfxFile", Description = "The PFX file that contains the signing certificate (the CA used to issue the new device certificate).")]
        [FileExists]
        public string SigningCertPfxFile { get; set; }

        [Required]
        [Option("-q", LongName = "CAPfxFilePassword", Description = "The password of the CAPfxFile PFX file.")]
        public string SigningCertPassword { get; set; }

        public int OnExecute()
        {
            var (certificate, collection) = CertificateUtil.LoadCertificateAndCollectionFromPfx(SigningCertPfxFile, SigningCertPassword);
            if (certificate == null)
            {
                Console.Error.WriteLine($"Could not load a certificate with private key from {SigningCertPfxFile}.");
                return -1;
            }
            var newCert = CertificateUtil.CreateAndSignCertificate(SubjectName, certificate);
            CertificateUtil.SaveCertificateToPfxFile(
                $"{SubjectName}.pfx",
                NewCertPassword,
                newCert,
                certificate,
                collection);
            return 0;
        }
    }
}