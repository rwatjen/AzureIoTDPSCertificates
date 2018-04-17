using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RW.DPSCertificateTool
{
    class CertificateUtil
    {
        /// <summary>
        /// Save a certificate and its chain of trust to a PFX file.
        /// </summary>
        /// <param name="filename">Filename to save to. Will be overwritten 
        /// if it already exists.</param>
        /// <param name="password">Password which must be used when reading 
        /// the file later.</param>
        /// <param name="certificate">The certificate to save</param>
        /// <param name="chain">The full chain of trust to include in the file.
        /// If <c>null</c>, then only the certificate itself is saved.</param>
        internal static void SaveCertificateToPfxFile(string filename, string password,
            X509Certificate2 certificate, X509Certificate2 signingCert,
            X509Certificate2Collection chain)
        {
            var certCollection = new X509Certificate2Collection(certificate);
            if (chain != null)
            {
                certCollection.AddRange(chain);
            }
            if (signingCert != null)
            {
                var signingCertWithoutPrivateKey = ExportCertificatePublicKey(signingCert);
                certCollection.Add(signingCertWithoutPrivateKey);

            }
            var certBytes = certCollection.Export(X509ContentType.Pkcs12, password);
            File.WriteAllBytes(filename, certBytes);
        }

        internal static X509Certificate2 ExportCertificatePublicKey(X509Certificate2 certificate)
        {
            var publicKeyBytes = certificate.Export(X509ContentType.Cert);
            var signingCertWithoutPrivateKey = new X509Certificate2(publicKeyBytes);
            return signingCertWithoutPrivateKey;
        }

        internal static X509Certificate2 CreateCaCertificate(string subjectName, string certificatePassword,
            X509Certificate2 issuingCa)
        {
            using (var ecdsa = ECDsa.Create("ECDsa"))
            {
                ecdsa.KeySize = 256;
                var request = new CertificateRequest(
                    $"CN={subjectName}",
                    ecdsa,
                    HashAlgorithmName.SHA256);

                // set basic certificate contraints
                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, true, 12, true));

                // key usage: Digital Signature and Key Encipherment
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.KeyCertSign,
                        true));

                if (issuingCa != null)
                {
                    // set the AuthorityKeyIdentifier. There is no built-in 
                    // support, so it needs to be copied from the Subject Key 
                    // Identifier of the signing certificate and massaged slightly.
                    // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
                    var issuerSubjectKey = issuingCa.Extensions["Subject Key Identifier"].RawData;
                    var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
                    var authorityKeyIdentifier = new byte[segment.Count + 4];
                    // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
                    authorityKeyIdentifier[0] = 0x30;
                    authorityKeyIdentifier[1] = 0x16;
                    authorityKeyIdentifier[2] = 0x80;
                    authorityKeyIdentifier[3] = 0x14;
                    segment.CopyTo(authorityKeyIdentifier, 4);
                    request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
                }
                // DPS samples create certs with the device name as a SAN name 
                // in addition to the subject name
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(subjectName);
                var sanExtension = sanBuilder.Build();
                request.CertificateExtensions.Add(sanExtension);

                // Enhanced key usages
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                        },
                        false));

                // add this subject key identifier
                request.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                // certificate expiry: Valid from Yesterday to Now+365 days
                // Unless the signing cert's validity is less. It's not possible
                // to create a cert with longer validity than the signing cert.
                var notbefore = DateTimeOffset.UtcNow.AddDays(-1);
                if ((issuingCa != null) && (notbefore < issuingCa.NotBefore))
                {
                    notbefore = new DateTimeOffset(issuingCa.NotBefore);
                }
                var notafter = DateTimeOffset.UtcNow.AddDays(365);
                if ((issuingCa != null) && (notafter > issuingCa.NotAfter))
                {
                    notafter = new DateTimeOffset(issuingCa.NotAfter);
                }

                // cert serial is the epoch/unix timestamp
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
                var serial = BitConverter.GetBytes(unixTime);

                X509Certificate2 generatedCertificate = null;
                if (issuingCa != null)
                {
                    generatedCertificate = request.Create(issuingCa, notbefore, notafter, serial);
                    return generatedCertificate.CopyWithPrivateKey(ecdsa);
                }
                else
                {
                    generatedCertificate = request.CreateSelfSigned(
                        notbefore, notafter);
                    return generatedCertificate;
                }
            }
        }

        /// <summary>
        /// Import a PFX file. The first certificate with a private key is 
        /// returned in the <c>certificate</c> value of the return tuple, 
        /// and remaining certificates are returned in the <c>collection</c>
        /// value.
        /// </summary>
        /// <param name="pfxFileName">.pfx file to import/read from</param>
        /// <param name="password">Password to the PFX file.</param>
        /// <returns>a Tuple of <see cref="X509Certificate2"/> and 
        /// <see cref="X509Certificate2Collection"/>
        /// with the contents of the PFX file.</returns>
        internal static (X509Certificate2 certificate, X509Certificate2Collection collection)
            LoadCertificateAndCollectionFromPfx(string pfxFileName, string password)
        {
            if (string.IsNullOrEmpty(pfxFileName))
            {
                throw new ArgumentException($"{nameof(pfxFileName)} must be a valid filename.", nameof(pfxFileName));
            }
            if (!File.Exists(pfxFileName))
            {
                throw new FileNotFoundException($"{pfxFileName} does not exist. Cannot load certificate from non-existing file.", pfxFileName);
            }
            var certificateCollection = new X509Certificate2Collection();
            certificateCollection.Import(
                pfxFileName,
                password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

            X509Certificate2 certificate = null;
            var outcollection = new X509Certificate2Collection();
            foreach (X509Certificate2 element in certificateCollection)
            {
                Console.WriteLine($"Found certificate: {element?.Thumbprint} " +
                    $"{element?.Subject}; PrivateKey: {element?.HasPrivateKey}");
                if (certificate == null && element.HasPrivateKey)
                {
                    certificate = element;
                }
                else
                {
                    outcollection.Add(element);
                }
            }

            if (certificate == null)
            {
                Console.WriteLine($"ERROR: {pfxFileName} did not " +
                    $"contain any certificate with a private key.");
                return (null, null);
            }
            else
            {
                Console.WriteLine($"Using certificate {certificate.Thumbprint} " +
                    $"{certificate.Subject}");
                return (certificate, outcollection);
            }

        }

        /// <summary>
        /// Creates a new certificate with the given subject name and signs it with the 
        /// certificate contained in the <paramref name="signingCertificate"/> parameter.
        /// </summary>
        /// <remarks>The generated certificate has the same attributes as the ones created
        /// by the IoT Hub Device Provisioning samples</remarks>
        /// <param name="subjectName">Subject name to give the new certificate</param>
        /// <param name="signingCertificate">Certificate to sign the new certificate with</param>
        /// <returns>A signed <see cref="X509Certificate2"/>.</returns>
        internal static X509Certificate2 CreateAndSignCertificate(string subjectName, X509Certificate2 signingCertificate)
        {
            if (signingCertificate == null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }
            if (!signingCertificate.HasPrivateKey)
            {
                throw new Exception("Signing cert must have private key");
            }
            if (string.IsNullOrEmpty(subjectName))
            {
                throw new ArgumentException($"{nameof(subjectName)} must be a valid DNS name", nameof(subjectName));
            }
            if (UriHostNameType.Unknown == Uri.CheckHostName(subjectName))
            {
                throw new ArgumentException("Must be a valid DNS name", nameof(subjectName));
            }

            using (var ecdsa = ECDsa.Create("ECDsa"))
            {
                ecdsa.KeySize = 256;
                var request = new CertificateRequest(
                    $"CN={subjectName}",
                    ecdsa,
                    HashAlgorithmName.SHA256);

                // set basic certificate contraints
                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                // key usage: Digital Signature and Key Encipherment
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                        true));

                // set the AuthorityKeyIdentifier. There is no built-in 
                // support, so it needs to be copied from the Subject Key 
                // Identifier of the signing certificate and massaged slightly.
                // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
                var issuerSubjectKey = signingCertificate.Extensions["Subject Key Identifier"].RawData;
                var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
                var authorityKeyIdentifer = new byte[segment.Count + 4];
                // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
                authorityKeyIdentifer[0] = 0x30;
                authorityKeyIdentifer[1] = 0x16;
                authorityKeyIdentifer[2] = 0x80;
                authorityKeyIdentifer[3] = 0x14;
                segment.CopyTo(authorityKeyIdentifer, 4);
                request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifer, false));

                // DPS samples create certs with the device name as a SAN name 
                // in addition to the subject name
                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName(subjectName);
                var sanExtension = sanBuilder.Build();
                request.CertificateExtensions.Add(sanExtension);

                // Enhanced key usages
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                        },
                        false));

                // add this subject key identifier
                request.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                // certificate expiry: Valid from Yesterday to Now+365 days
                // Unless the signing cert's validity is less. It's not possible
                // to create a cert with longer validity than the signing cert.
                var notbefore = DateTimeOffset.UtcNow.AddDays(-1);
                if (notbefore < signingCertificate.NotBefore)
                {
                    notbefore = new DateTimeOffset(signingCertificate.NotBefore);
                }
                var notafter = DateTimeOffset.UtcNow.AddDays(365);
                if (notafter > signingCertificate.NotAfter)
                {
                    notafter = new DateTimeOffset(signingCertificate.NotAfter);
                }

                // cert serial is the epoch/unix timestamp
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
                var serial = BitConverter.GetBytes(unixTime);

                // create and return the generated and signed
                using (var cert = request.Create(
                    signingCertificate,
                    notbefore,
                    notafter,
                    serial))
                {
                    return cert.CopyWithPrivateKey(ecdsa);
                }
            }
        }
    }
}
