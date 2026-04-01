/* ****************************************************************************

 * eID Middleware Project.
 * Copyright (C) 2010-2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.

**************************************************************************** */

// Doc pkcs11 : https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html

using System;
using System.Collections.Generic;

using System.Text;

using System.Runtime.InteropServices;

using Net.Sf.Pkcs11;
using Net.Sf.Pkcs11.Objects;
using Net.Sf.Pkcs11.Wrapper;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Timers;
using PublicKey = Net.Sf.Pkcs11.Objects.PublicKey;

using U_INT =
#if Windows
        System.UInt32;
using System.Threading;
#else
		System.UInt64;
using System.IO;
using System.Threading;
#endif

namespace EIDLib
{
    
    public class ReadData : IDisposable
    {
        public static SemaphoreSlim _asyncLocker = new SemaphoreSlim(1, 1);
        /// <summary>
        /// If card is plugged (Used by Detection event)
        /// /!\ if you modify that /!\
        /// </summary>
        public bool IsRead = false;
        private Thread _pollingThread;
        private bool _isDisposed = false;

        public delegate void Detection(string output, bool IsPlugged);
        /// <summary>
        /// Detect if identity card is plugged or no
        /// </summary>
        public event Detection Detect;
        public static Module module = null;
        private String mFileName;

        /// <summary>
        /// Show instance count in app
        /// </summary>
        public static int InstanceCount => _instanceCount;

        private static int _instanceCount = 0;

        /// <summary>
        /// Default constructor. Will instantiate the beidpkcs11.dll pkcs11 module
        /// </summary>
        public ReadData()
        {
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                mFileName = @"beidpkcs11.dll";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                mFileName = "libbeidpkcs11.dylib";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                mFileName = "libbeidpkcs11.so";
            }
            
            try
            {
                if (IsCardPresent())
                {
                    IsRead = true;
                }
                else
                {
                    IsRead = false;
                }
            }
            catch (Exception e)
            {
                IsRead = false;
            }


            if(_instanceCount == 0) // On évite d'avoir 2 thread de détection de carte actif
            {
                // Pour la détection de la carte
                _pollingThread = new Thread(PollCardReader);
                _pollingThread.IsBackground = true; // S'arrête tout seul quand le programme se ferme
                _pollingThread.Name = "eID_Hardware_Polling";
                _pollingThread.Start();
            }
            else
            {
                Console.WriteLine("Thead de détection de carte EID désactivé pour cause d'instances multiples");
            }

            _instanceCount += 1;
        }

        /// <summary>
        /// Check if a card is present
        /// </summary>
        /// <returns>Present or not</returns>
        public bool IsCardPresent()
        {
            if (!_asyncLocker.Wait(100))
            {
                return false;
            }

            try
            {
                if (module == null)
                {
                    module = Module.GetInstance(mFileName);
                }

                // On demande juste au pilote si un lecteur contient un token
                Slot[] slots = module.GetSlotList(true);
                return (slots != null && slots.Length > 0);
            }
            catch
            {
                // Si le pilote renvoie une erreur pendant le retrait, on l'absorbe
                return false;
            }
            finally
            {
                _asyncLocker.Release();
            }
        }

        private void PollCardReader()
        {
            try
            {
                if (module == null)
                {
                    module = Module.GetInstance(mFileName);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            while (!_isDisposed)
            {
                if (Detect != null)
                {
                    
                    try
                    {
                        try
                        {
                            module.WaitForSlotEvent(
                                false); // Bloque ici tant qu'on a pas un évennement du lecteur de carte (insertion ou retrait)

                        }
                        catch (TokenException e)
                        {
                            if (e.ErrorCode == CKR.FUNCTION_NOT_SUPPORTED)
                            {
                                Thread.Sleep(200); // Si FUNCTION_NOT_SUPPORTED => On patiente 200 ms pour checker
                            }
                            else
                            {
                                Console.WriteLine(e.Message);
                                return;
                            }

                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                            return;
                        }
                        
                        if (IsRead)
                        {
                            if (!IsCardPresent())
                            {
                                IsRead = false;
                                if (Detect != null)
                                    Detect("Identity card unplugged", false);
                            }
                        }
                        else
                        {

                            if (IsCardPresent())
                            {
                                IsRead = true;

                                if (Detect != null)
                                    Detect("Identity card plugged", true);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Erreur {e?.Message}");
                    }
                }

            }
        }

        public void Dispose()
        {
            try
            {
                
                //module?.Dispose();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                //module = null;
                _isDisposed = true;
                _instanceCount -= 1;
                
                Thread.Sleep(200);
            }
        }

        /// <summary>
        /// Name of native library (beidpkcs11)
        /// </summary>
        /// <param name="moduleFileName"></param>
        public ReadData(String moduleFileName)
        {
            mFileName = moduleFileName;
        }

        /// <summary>
        /// Gets the description of the first slot (cardreader) found
        /// </summary>
        /// <returns>Description of the first slot found</returns>
        public string GetSlotDescription()
        {
            String slotID;
            if (module == null)
            {
                module = Module.GetInstance(mFileName);
            }
            //initialization now occurs within the getinstance function
            //m.Initialize();
            try
            {
                // Look for slots (cardreaders)
                // GetSlotList(false) will return all cardreaders
                Slot[] slots = module.GetSlotList(false);
                if (slots.Length == 0)
                    slotID = "";
                else
                    slotID = slots[0].SlotInfo.SlotDescription.Trim();
            }
            finally
            {
                //m.Finalize_();
                //m.Dispose();
                //m = null;
            }
            return slotID;
        }


        /// <summary>
        /// Tries to create a Session, returns NULL in case of failure
        /// </summary>
        /// <returns></returns>
        private Session CreateSession (Slot slot )
        {
            try
            {
                return slot.Token.OpenSession(true);
            }
            catch
            {
                return null;
            }       
        }

        /// <summary>
        /// Gets label of token found in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetTokenInfoLabel()
        {
            String tokenInfoLabel;
            if (module == null)
            {
                module = Module.GetInstance(mFileName);
            }
            //m.Initialize();
            try
            {
                // Look for slots (cardreaders)
                // GetSlotList(true) will return only the cardreaders with a 
                // token (smart card)
                tokenInfoLabel = module.GetSlotList(true)[0].Token.TokenInfo.Label.Trim();
            }
            finally
            {
                //m.Dispose();//m.Finalize_();
                //m = null;
            }
            return tokenInfoLabel;

        }

        // PARSED DATA

        /// <summary>
        /// Get card number of the owner of the token (eid) in the first non-empty slot [HEX] (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetCardNumber()
        {
            return GetData("card_number");
        }

        /// <summary>
        /// Get chip number of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetChipNumber()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes("chip_number"));
        }

        /// <summary>
        /// Get validity begin date of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetValidityBeginDate()
        {
            return GetData("validity_begin_date");
        }

        /// <summary>
        /// Get validity end date of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetValidityEndDate()
        {
            return GetData("validity_end_date");
        }

        /// <summary>
        /// Get issuing municipality of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetIssuingMunicipality()
        {
            return GetData("issuing_municipality");
        }

        /// <summary>
        /// Get national number of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetNationalNumber()
        {
            return GetData("national_number");
        }

        /// <summary>
        /// Get surname of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetSurname()
        {
            return GetData("surname");
        }
        
        

        /// <summary>
        /// Get firstnames of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetFirstnames()
        {
            return GetData("firstnames");
        }

        /// <summary>
        /// Get first letter of third given name of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetFirstLetterOfThirdGivenName()
        {
            return GetData("first_letter_of_third_given_name");
        }

        /// <summary>
        /// Get nationality of the owner of the token (eid) in the first non-empty slot (cardreader)
        /// </summary>
        /// <returns></returns>
        public string GetNationality()
        {
            return GetData("nationality");
        }

        /// <summary>
        /// Get location of birth of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetLocationOfBirth()
        {
            return GetData("location_of_birth");
        }

        /// <summary>
        /// Get date of birth of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetDateOfBirth()
        {
            return GetData("date_of_birth");
        }

        /// <summary>
        /// Get gender of the owner. (M/F/V/W) This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetGender()
        {
            return GetData("gender");
        }

        /// <summary>
        /// Get nobility of the owner. (Noble condition) This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetNobility()
        {
            return GetData("nobility");
        }
        
        /// <summary>
        /// Get document type of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetDocumentType()
        {
            return GetData("document_type");
        }

        /// <summary>
        /// Get special status of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetSpecialStatus()
        {
            return GetData("special_status");
        }

        /// <summary>
        /// Get hash of the photo file of the owner. This is a language specific string [HEX (SHA-384)]
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetPhotoHash()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes("photo_hash"));
        }

        /// <summary>
        /// Get duplicata of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetDuplicata()
        {
            return GetData("duplicata");
        }

        /// <summary>
        /// Get special organization of the owner. (1: SHAPE, 2: NATO) This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetSpecialOrganization()
        {
            return GetData("special_organization");
        }

        /// <summary>
        /// Get member of family of the owner. (bool) This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetMemberOfFamily()
        {
            return GetData("member_of_family");
        }

        /// <summary>
        /// Get date and country of protection of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetDateAndCountryOfProtection()
        {
            return GetData("date_and_country_of_protection");
        }
    
        /// <summary>
        /// Get work permit mention of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetWorkPermitMention()
        {
            return GetData("work_permit_mention");
        }

        /// <summary>
        /// Get employer vat 1 of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetEmployerVat1()
        {
            return GetData("employer_vat_1");
        }

        /// <summary>
        /// Get employer vat 2 of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetEmployerVat2()
        {
            return GetData("employer_vat_2");
        }

        /// <summary>
        /// Get regional file number of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetRegionalFileNumber()
        {
            return GetData("regional_file_number");
        }

        /// <summary>
        /// Get basic key hash of the owner. SHA384 hash of the public basic key. (applet 1.8+) This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetBasicKeyHash()
        {
            return GetData("basic_key_hash");
        }

        /// <summary>
        /// Get brexit mention 1 of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetBrexitMention1()
        {
            return GetData("brexit_mention_1");
        }

        /// <summary>
        /// Get brexit mention 2 of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetBrexitMention2()
        {
            return GetData("brexit_mention_2");
        }

        /// <summary>
        /// Get streetname and number of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetAddressStreetAndNumber()
        {
            return GetData("address_street_and_number");
        }

        /// <summary>
        /// Get address zip of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetAddressZip()
        {
            return GetData("address_zip");
        }

        /// <summary>
        /// Get address municipality of the owner. This is a language specific string
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetAddressMunicipality()
        {
            return GetData("address_municipality");
        }


        // CARD INFO

        private string BytesToHEXStringConverter(byte[] ba)
        {
            char[] c = new char[ba.Length * 2];
            for( int i = 0; i < ba.Length * 2; ++i)
            {
                byte b = (byte)((ba[i>>1] >> 4*((i&1)^1)) & 0xF);
                c[i] = (char)(55 + b + (((b-10)>>31)&-7));
            }
            return new string( c );
        }

        /// <summary>
        /// Get card serial number (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardSerialNumber()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_serialnumber")));
        }

        /// <summary>
        /// Get card comp code (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardCompCode()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_comp_code")));
        }

        /// <summary>
        /// Get card OS number (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardOSNumber()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_os_number")));
        }

        /// <summary>
        /// Get card OS version (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardOSVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_os_version")));
        }

        /// <summary>
        /// Get soft mask number (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardSoftMaskNumber()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_soft_mask_number")));
        }

        /// <summary>
        /// Get soft mask version (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardSoftMaskVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_soft_mask_version")));
        }

        /// <summary>
        /// Get card applet version [Applet +1.7] (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardAppletVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_appl_version")));
        }

        /// <summary>
        /// Get glob OS version [Applet +1.7] (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardGlobOSVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_glob_os_version")));
        }

        /// <summary>
        /// Get card applet int version (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardAppletIntVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_appl_int_version")));
        }

        /// <summary>
        /// Get PKCS1 Support [Applet +1.7] (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardPKCS1Support()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_pkcs1_support")));
        }

        /// <summary>
        /// Get applet life cycle [Applet +1.7] (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardAppletLifeCycle()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_appl_lifecycle")));
        }

        /// <summary>
        /// Get PKCS1 Support [Applet +1.7] (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardPKCS15Version()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_pkcs15_version")));
        }

        /// <summary>
        /// Get key exchange version (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        public string GetCardKeyExchangeVersion()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_key_exchange_version")));
        }

        /// <summary>
        /// Get Signature (not yet available) (HEX)
        /// More info about the format can be found in the eid specs.
        /// </summary>
        /// <returns></returns>
        [Obsolete("Not yet available")]
        public string GetCardSignature()
        {
            return BytesToHEXStringConverter(Encoding.UTF8.GetBytes(GetData("carddata_signature")));
        }

        /// <summary>
        /// Generic function to get string data objects from label
        /// </summary>
        /// <param name="label">Value of label attribute of the object</param>
        /// <returns></returns>
        public string GetData(String label)
        {
            String value = "";
            _asyncLocker.Wait();

            try
            {
                if (module == null) module = Module.GetInstance(mFileName);

                Slot[] slotlist = module.GetSlotList(true);
                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];
                    Session session = CreateSession(slot);
                    if (session != null)
                    {
                        try
                        {
                            ByteArrayAttribute classAttribute = new ByteArrayAttribute(CKA.CLASS);
                            classAttribute.Value = BitConverter.GetBytes((U_INT)CKO.DATA);

                            ByteArrayAttribute labelAttribute = new ByteArrayAttribute(CKA.LABEL);
                            labelAttribute.Value = Encoding.UTF8.GetBytes(label);

                            P11Attribute[] searchTemplate = new P11Attribute[] { classAttribute, labelAttribute };

                            session.FindObjectsInit(searchTemplate);

                            // OPTIMISATION : On demande 1 seul objet au lieu de 50
                            P11Object[] foundObjects = session.FindObjects(1);

                            if (foundObjects != null && foundObjects.Length > 0)
                            {
                                Data data = foundObjects[0] as Data;
                                if (data?.Value?.Value != null)
                                {
                                    value = Encoding.UTF8.GetString(data.Value.Value);
                                }
                            }
                            session.FindObjectsFinal();

                            GC.KeepAlive(searchTemplate);
                            GC.KeepAlive(classAttribute);
                            GC.KeepAlive(labelAttribute);
                        }
                        finally
                        {
                            session?.Dispose();
                        }
                    }
                }
                else
                {
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
            finally
            {
                _asyncLocker.Release();
            }
            return value;
        }

        public void GetAndTestIdFile()
        {
            ReadData dataTest = null;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                dataTest = new ReadData(@"beidpkcs11.dll");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                dataTest = new ReadData("libbeidpkcs11.dylib");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                dataTest = new ReadData("libbeidpkcs11.so");
            }

            Integrity integrityTest = new Integrity();
            byte[] idFile = dataTest.GetIdFile();
            byte[] idSignatureFile = dataTest.GetIdSignatureFile();
            //byte[] certificateRRN = null;
            //Assert.isFalse(integrityTest.Verify(idFile, idSignatureFile, certificateRRN));
        }
        
        /// <summary>
        /// Return ID data file contents
        /// </summary>
        /// <returns></returns>
        public byte[] GetIdFile()
        {
            return GetFile("DATA_FILE");
        }
        /// <summary>
        /// Return Address file contents
        /// </summary>
        /// <returns></returns>
        public byte[] GetAddressFile()
        {
            return GetFile("ADDRESS_FILE");
        }
        /// <summary>
        /// Return Photo file contents
        /// </summary>
        /// <returns></returns>
        public byte[] GetPhotoFile()
        {
            return GetFile("PHOTO_FILE");
        }
        /// <summary>
        /// Return ID file signature
        /// </summary>
        /// <returns></returns>
        public byte[] GetIdSignatureFile()
        {
            return GetFile("SIGN_DATA_FILE");
        }
        /// <summary>
        /// Return Address file signature
        /// </summary>
        /// <returns></returns>
        public byte[] GetAddressSignatureFile()
        {
            return GetFile("SIGN_ADDRESS_FILE");
        }
        /// <summary>
        /// Return RRN Certificate. This certificate is used to validate
        /// the file signatures
        /// </summary>
        /// <returns></returns>
        public byte[] GetCertificateRNFile()
        {
            return GetFile("CERT_RN_FILE");
        }

        /// <summary>
        /// Return raw byte data from objects
        /// </summary>
        /// <param name="Filename">Label value of the object</param>
        /// <returns>byte array with file</returns>
        private byte[] GetFile(String Filename)
        {
            byte[] value = null;
            _asyncLocker.Wait();

            try
            {
                if (module == null) module = Module.GetInstance(mFileName);

                Slot[] slotlist = module.GetSlotList(true);
                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];
                    Session session = CreateSession(slot);
                    if (session != null)
                    {
                        try
                        {
                            ByteArrayAttribute fileLabel = new ByteArrayAttribute(CKA.LABEL);
                            fileLabel.Value = System.Text.Encoding.UTF8.GetBytes(Filename);

                            ByteArrayAttribute fileData = new ByteArrayAttribute(CKA.CLASS);
                            fileData.Value = BitConverter.GetBytes((U_INT)Net.Sf.Pkcs11.Wrapper.CKO.DATA);

                            P11Attribute[] searchTemplate = new P11Attribute[] { fileLabel, fileData };
                            session.FindObjectsInit(searchTemplate);

                            P11Object[] foundObjects = session.FindObjects(1);
                            if (foundObjects != null && foundObjects.Length != 0)
                            {
                                Data file = foundObjects[0] as Data;
                                value = file?.Value?.Value;
                            }
                            session.FindObjectsFinal();

                            GC.KeepAlive(searchTemplate);
                            GC.KeepAlive(fileLabel);
                            GC.KeepAlive(fileData);
                        }
                        finally
                        {
                            session?.Dispose();
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                _asyncLocker.Release();
            }
            return value;
        }
        
        
        /// <summary>
        /// Return the "authentication" leaf certificate file
        /// </summary>
        /// <returns></returns>
        public byte[] GetCertificateAuthenticationFile()
        {
            return GetCertificateFile("Authentication");
        }
        /// <summary>
        /// Return the "signature" leaf certificate file
        /// </summary>
        /// <returns></returns>
        public byte[] GetCertificateSignatureFile()
        {
            return GetCertificateFile("Signature");
        }
        /// <summary>
        /// Return the Intermediate CA certificate file
        /// </summary>
        /// <returns></returns>
        public byte[] GetCertificateCAFile()
        {
            return GetCertificateFile("CA");
        }
        /// <summary>
        /// Return the root certificate file
        /// </summary>
        /// <returns></returns>
        public byte[] GetCertificateRootFile()
        {
            return GetCertificateFile("Root");
        }
        /// <summary>
        /// Return raw byte data from objects of object class Certificate
        /// </summary>
        /// <param name="Certificatename">Label value of the certificate object</param>
        /// <returns>byte array with certificate file</returns>
        private byte[] GetCertificateFile(String Certificatename)
        {
            byte[] value = null;
            _asyncLocker.Wait();

            try
            {
                if (module == null) module = Module.GetInstance(mFileName);

                Slot[] slotlist = module.GetSlotList(true);
                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];
                    Session session = CreateSession(slot);
                    if (session != null)
                    {
                        try
                        {
                            ByteArrayAttribute fileLabel = new ByteArrayAttribute(CKA.LABEL);
                            fileLabel.Value = System.Text.Encoding.UTF8.GetBytes(Certificatename);

                            ObjectClassAttribute certificateAttribute = new ObjectClassAttribute(CKO.CERTIFICATE);

                            P11Attribute[] searchTemplate = new P11Attribute[] { certificateAttribute, fileLabel };
                            session.FindObjectsInit(searchTemplate);

                            P11Object[] foundObjects = session.FindObjects(1);
                            if (foundObjects != null && foundObjects.Length != 0)
                            {
                                X509PublicKeyCertificate cert = foundObjects[0] as X509PublicKeyCertificate;
                                value = cert?.Value?.Value;
                            }
                            session.FindObjectsFinal();

                            GC.KeepAlive(searchTemplate);
                            GC.KeepAlive(fileLabel);
                            GC.KeepAlive(certificateAttribute);
                        }
                        finally
                        {
                            session?.Dispose();
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                _asyncLocker.Release();
            }
            return value;
        }
        
        
        /// <summary>
        /// Returns a list of PKCS11 labels of the certificate on the card
        /// </summary>
        /// <returns>List of labels of certificate objects</returns>
        public List<string> GetCertificateLabels()
        {
            
            _asyncLocker.Wait();
            
            // pkcs11 module init
            if (module == null)
            {
                module = Module.GetInstance(mFileName);
            }
            //m.Initialize();
            List<string> labels = new List<string>();
            try
            {
                // Get the first slot (cardreader) with a token
                Slot[] slotlist = module.GetSlotList(true);

                if (slotlist == null)
                {
                    Console.WriteLine("No card reader found");
                    throw new Exception("No card reader found");
                }


                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];
                    Session session = slot.Token.OpenSession(true);
                    // Search for objects
                    // First, define a search template 

                    // "The object class of the objects should be "certificate"" 
                    ObjectClassAttribute certificateAttribute = new ObjectClassAttribute(CKO.CERTIFICATE);
                    session.FindObjectsInit(new P11Attribute[] {
                     certificateAttribute
                    }
                    );


                    P11Object[] certificates = session.FindObjects(100) as P11Object[];
                    foreach (P11Object certificate in certificates)
                    {
                        labels.Add(new string(((X509PublicKeyCertificate)certificate).Label.Value));
                    }
                    session.FindObjectsFinal();
                }
                else
                {
                    Console.WriteLine("No card found\n");
                    throw new Exception("No card found");
                }
            }
            finally
            {
                _asyncLocker.Release();
                // pkcs11 finalize
                //m.Dispose();//m.Finalize_();
                //m = null;
            }
            return labels;
        }

        /// <summary>
        /// Return raw byte data from objects of object class Public Key
        /// </summary>
        /// <param name="PubKeyName">Label value of the key object</param>
        /// <returns>ECPublicKey object of the public key found</returns>
        public ECPublicKey GetPublicKey(String PubKeyName)
        {
            _asyncLocker.Wait();
            
            ECPublicKey eCPublicKey = null;
            // pkcs11 module init
            if (module == null)
            {
                module = Module.GetInstance(mFileName);
            }
            try
            {
                // Get the first slot (cardreader) with a token
                Slot[] slotlist = module.GetSlotList(true);

                if (slotlist == null)
                {
                    Console.WriteLine("No card reader found");
                    throw new Exception("No card reader found");
                }

                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];

                    Session session = slot.Token.OpenSession(true);
                    // Search for objects
                    // First, define a search template 

                    // The label attribute of the objects should equal PubKeyName
                    ObjectClassAttribute classAttribute = new ObjectClassAttribute(CKO.PUBLIC_KEY);
                    ByteArrayAttribute keyLabelAttribute = new ByteArrayAttribute(CKA.LABEL);
                    keyLabelAttribute.Value = System.Text.Encoding.UTF8.GetBytes(PubKeyName);

                    session.FindObjectsInit(new P11Attribute[] { classAttribute, keyLabelAttribute });
                    //P11Object[] pubkeys = session.FindObjects(1) as P11Object[];
                    P11Object[] pubkeys = session.FindObjects(1);
                    session.FindObjectsFinal();

                    if ( (pubkeys.Length == 0) || (pubkeys[0] == null) )
                    {
                        Console.WriteLine("Public Key Object not found");
                        return eCPublicKey;
                    }
                    eCPublicKey = (ECPublicKey)pubkeys[0];
                  //  session.FindObjectsFinal();
                }
                else
                {
                    Console.WriteLine("No card found\n");
                    throw new Exception("No card found");
                }
            }
            finally
            {
                _asyncLocker.Release();
                // pkcs11 finalize
                //m.Dispose();//m.Finalize_();
                //m = null;
            }
            return eCPublicKey;
        }
    }
}
