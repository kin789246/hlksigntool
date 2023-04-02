using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Security.Cryptography.X509Certificates;

namespace hlksigntool
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                System.Console.WriteLine("Usage: hlksigntool.exe [verify|sign] [hlkx file name]");
                return 1;
            }

            string action = args[0];
            string file_name = args[1];
            const string cerName = "CN=\"COMPAL ELECTRONICS, INC.\"";

            if (action == "verify" || action == "v")
            {
                try
                {

                    Package package = Package.Open(file_name, FileMode.Open, FileAccess.Read);
                    PackageDigitalSignatureManager signatureManager = new PackageDigitalSignatureManager(package);

                    bool isSigned = false;
                    foreach (var part in package.GetParts())
                    {
                        if (signatureManager.GetSignature(part.Uri) != null)
                        {
                            isSigned = true;
                        }
                    }

                    package.Close();

                    if (isSigned)
                    {
                        System.Console.WriteLine("Package is singned.");
                    }
                    else
                    {
                        System.Console.WriteLine("Package is NOT singned.");
                    }
                }
                catch (Exception e)
                {
                    System.Console.WriteLine(e.Message);
                    return 1;
                }
            }
            else if (action == "sign" || action == "s")
            {
                try
                {
                    Package package = Package.Open(file_name, FileMode.Open, FileAccess.ReadWrite);
                    PackageDigitalSignatureManager signatureManager = new PackageDigitalSignatureManager(package);
                    List<PackageRelationshipSelector> relationshipSelectors = new List<PackageRelationshipSelector>();

                    foreach (PackageRelationship relationship in package.GetRelationships())
                    {
                        relationshipSelectors.Add(new PackageRelationshipSelector(
                            relationship.SourceUri, PackageRelationshipSelectorType.Type, relationship.RelationshipType)
                            );
                    }

                    X509Certificate2 cert = GetCertificateFromStore(cerName);
                    if (cert == null)
                    {
                        Console.WriteLine("Certificate {0} not found.", cerName);
                        return 1;
                    }

                    List<Uri> partsToSign = new List<Uri>();
                    foreach (PackagePart part in package.GetParts())
                    {
                        partsToSign.Add(part.Uri);
                    }
                    signatureManager.Sign(partsToSign, cert, relationshipSelectors);

                    package.Close();
                }
                catch (Exception e)
                {
                    System.Console.WriteLine(e.Message);
                    return 1;
                }
            }
            else
            {
                System.Console.WriteLine("Usage: hlksigntool.exe [verify|sign] [hlkx file name]");
                return 1;
            }
            return 0;
        }

        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                //X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                //X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);

                foreach (X509Certificate2 x509 in certCollection)
                {
                    if (x509.Subject.Contains(certName))
                    {
                        return x509;
                    }
                }

                return null;
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                store.Close();
            }
        }
    }
}
