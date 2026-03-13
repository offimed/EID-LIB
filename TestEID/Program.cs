using System;
using System.Text;
using System.Timers;
using EIDLib;

namespace TestEID
{
    class Program
    {
        static void Main(string[] args)
        {
            Settings.SetLanguage(Settings.Language.fr);

            ReadData data = new ReadData();

            // Identity card detection tests
            

            data.Detect += (output, isPlugged) =>
            {
                Console.WriteLine($"{output} => PLUGGED: {isPlugged}");

                if (isPlugged) // Card is plugged
                {
                    try
                    {
                        Console.WriteLine(data.GetFirstnames());
                        Console.WriteLine(data.GetSurname());
                        Console.WriteLine(data.GetDateOfBirth());
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            };

            Console.ReadKey();
            
            data.Dispose();
            data = null;
            //System.Security.Cryptography.X509Certificates.X509Certificate2 cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(data.GetCertificateAuthenticationFile());
            
            /*
            
            // Parsed from data file

            data.GetAndTestIdFile();

            Console.WriteLine(data.GetFirstnames());

            Console.WriteLine(data.GetSurname());

            Console.WriteLine(data.GetDateOfBirth());

            //Console.WriteLine(data.GetBasicKeyHash()); // Applet 1.8

            Console.WriteLine(data.GetBrexitMention1());

            Console.WriteLine(data.GetBrexitMention2());

            Console.WriteLine(data.GetCardNumber());

            Console.WriteLine(data.GetChipNumber());

            Console.WriteLine(data.GetDateAndCountryOfProtection());

            Console.WriteLine(data.GetDocumentType());

            Console.WriteLine(data.GetDuplicata());

            Console.WriteLine(data.GetEmployerVat1());

            Console.WriteLine(data.GetEmployerVat2());

            Console.WriteLine(data.GetFirstLetterOfThirdGivenName());

            Console.WriteLine(data.GetGender());

            Console.WriteLine(data.GetIssuingMunicipality());

            Console.WriteLine(data.GetLocationOfBirth());

            Console.WriteLine(data.GetMemberOfFamily());

            Console.WriteLine(data.GetNationality());

            Console.WriteLine(data.GetNationalNumber());

            Console.WriteLine(data.GetNobility());

            Console.WriteLine(data.GetPhotoHash());

            Console.WriteLine(data.GetRegionalFileNumber());

            Console.WriteLine(data.GetSpecialOrganization());

            Console.WriteLine(data.GetSpecialStatus());

            Console.WriteLine(data.GetValidityBeginDate());

            Console.WriteLine(data.GetValidityEndDate());

            Console.WriteLine(data.GetWorkPermitMention());


            // Parsed from address file

            Console.WriteLine(data.GetAddressMunicipality());

            Console.WriteLine(data.GetAddressStreetAndNumber());

            Console.WriteLine(data.GetAddressZip());

            // Card info

            Console.WriteLine(data.GetCardSerialNumber());

            Console.WriteLine(data.GetCardAppletVersion());

            Console.WriteLine(data.GetCardAppletIntVersion());

            Console.WriteLine(data.GetCardAppletLifeCycle());

            Console.WriteLine(data.GetCardCompCode());

            Console.WriteLine(data.GetCardGlobOSVersion());

            Console.WriteLine(data.GetCardKeyExchangeVersion());

            Console.WriteLine(data.GetCardOSNumber());

            Console.WriteLine(data.GetCardOSVersion());

            Console.WriteLine(data.GetCardPKCS15Version());

            Console.WriteLine(data.GetCardPKCS1Support());

            Console.WriteLine(data.GetCardSoftMaskNumber());

            Console.WriteLine(data.GetCardSoftMaskVersion());

            //Console.WriteLine(data.GetCardSignature()); // NOT YET AVAILABLE
            */
            // Test electronic signature

            Integrity integrity = new Integrity();
            Sign signer = new Sign();

            string ASigner = "Hello World";

            var signed = signer.DoSign(Encoding.ASCII.GetBytes(ASigner), "Signature");
            
            var verif = integrity.Verify(Encoding.ASCII.GetBytes(ASigner), signed, data.GetCertificateSignatureFile());

            Console.ReadLine();
        }
    }
}
