
using System;
using System.Collections.Generic;
using System.Net;
using Net.Sf.Pkcs11.Delegates;
using System.Runtime.InteropServices;

using U_INT =
#if Windows
		System.UInt32;
#else
		System.UInt64;
#endif

namespace Net.Sf.Pkcs11.Wrapper
{

	/// <summary>
    /// Wrapper around Pkcs11 (low-level).
	/// </summary>
	public class Pkcs11Module
	{
		/// <summary>
		/// 
		/// </summary>
		protected IntPtr hLib;
		
		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="hLib"></param>
        protected Pkcs11Module(IntPtr hLib)
        {
			this.hLib=	hLib;
		}
		
		/// <summary>
		/// Creates an instance of Pkcs11Module
		/// </summary>
		/// <param name="moduleName">
		/// module to be loaded. it is the path of pkcs11 driver
		/// <example>
		/// <code>
		/// Pkcs11Module pm=Pkcs11Module.GetInstance("gclib.dll");
		/// </code>
		/// </example>
		/// </param>
		/// <returns></returns>
		internal static Pkcs11Module GetInstance(string moduleName){
			IntPtr hLib;

			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				IKernelUtil kern = new KernelUtilWindows();
				if ((hLib = kern.LoadLibrary(moduleName)) == IntPtr.Zero)
					throw new Exception("Could not load module. Module name:" + moduleName);
			}
			else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
			{
				if ((hLib = new KernelUtilUNIX().LoadLibrary(moduleName)) == IntPtr.Zero) 
					if((hLib = new KernelUtilUNIX().LoadLibrary("/Library/Belgium Identity Card/Pkcs11/libbeidpkcs11.dylib")) == IntPtr.Zero)
						throw new Exception("Could not load module. Module name:" + moduleName);
			}
			else
			{
				if ((hLib = new KernelUtilUNIX().LoadLibrary(moduleName)) == IntPtr.Zero)
					throw new Exception("Could not load module. Module name:" + moduleName);
			}

			return new Pkcs11Module(hLib);
		}


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct C_INITIALIZE_ARGS
        {
            public IntPtr CreateMutex;
            public IntPtr DestroyMutex;
            public IntPtr LockMutex;
            public IntPtr UnlockMutex;
            public U_INT Flags; // IMPORTANT : U_INT au lieu de uint
            public IntPtr pReserved;
        }

        // 2. Un pointeur statique qui survivra à toute l'application
        private static IntPtr _pInitArgs = IntPtr.Zero;

        public void Initialize()
        {
            C_Initialize proc = (C_Initialize)DelegateUtil.GetDelegate(this.hLib, typeof(C_Initialize));

            // On ne l'alloue qu'une seule fois pour toute l'application
            if (_pInitArgs == IntPtr.Zero)
            {
                C_INITIALIZE_ARGS initArgs = new C_INITIALIZE_ARGS();
                initArgs.Flags = 2; // 2 = CKF_OS_LOCKING_OK (Autorise le multi-threading)

                _pInitArgs = Marshal.AllocHGlobal(Marshal.SizeOf(initArgs));
                Marshal.StructureToPtr(initArgs, _pInitArgs, false);
            }

            // On initialise, SANS utiliser de try/finally. 
            // On ne libère jamais _pInitArgs.
            checkCKR(proc(_pInitArgs));
        }
        //public void Initialize()
        //      {
        //          C_Initialize proc=(C_Initialize)DelegateUtil.GetDelegate(this.hLib,typeof(C_Initialize));
        //	checkCKR( proc(IntPtr.Zero));
        //}

        /// <summary>
        /// 
        /// </summary>
        public void Finalize_(){
			C_Finalize proc=(C_Finalize)DelegateUtil.GetDelegate(this.hLib,typeof(C_Finalize));
			checkCKR( proc(IntPtr.Zero));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public CK_INFO GetInfo()
		{
			C_GetInfo proc=(C_GetInfo)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetInfo));
			
			CK_INFO ckInfo=new CK_INFO();
			checkCKR( proc(ref ckInfo));
			
			return ckInfo;
		}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenPresent"></param>
        /// <returns></returns>
        public U_INT[] GetSlotList(bool tokenPresent)
        {
            C_GetSlotList proc = (C_GetSlotList)DelegateUtil.GetDelegate(this.hLib, typeof(C_GetSlotList));

            U_INT pullVal = 0;
            checkCKR(proc(tokenPresent, null, ref pullVal));

            if (pullVal == 0) return new U_INT[0]; // Sécurité anti-crash

            U_INT[] slots = new U_INT[pullVal];
            checkCKR(proc(tokenPresent, slots, ref pullVal));

            return slots;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="slotID"></param>
        /// <returns></returns>
        public CK_SLOT_INFO GetSlotInfo(U_INT slotID){
			
			C_GetSlotInfo proc=(C_GetSlotInfo)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetSlotInfo));
			
			CK_SLOT_INFO slotInfo=new CK_SLOT_INFO();
			checkCKR( proc(slotID, ref slotInfo));
			
			return slotInfo;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotID"></param>
		/// <returns></returns>
		public CK_TOKEN_INFO GetTokenInfo(U_INT slotID){
			
			C_GetTokenInfo proc=(C_GetTokenInfo)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetTokenInfo));
			
			CK_TOKEN_INFO tokenInfo=new CK_TOKEN_INFO();
			checkCKR( proc(slotID, ref tokenInfo));
			
			return tokenInfo;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="options"></param>
		/// <returns></returns>
		public U_INT WaitForSlotEvent(bool DO_NOT_BLOCK){
			
			C_WaitForSlotEvent proc=(C_WaitForSlotEvent)DelegateUtil.GetDelegate(this.hLib,typeof(C_WaitForSlotEvent));
			
			U_INT slotId=0, flags=0;
			
			if(DO_NOT_BLOCK)
				flags=PKCS11Constants.CKF_DONT_BLOCK;
			
			checkCKR(proc(flags, ref slotId, IntPtr.Zero));
			
			return slotId;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotId"></param>
		/// <returns></returns>
		public CKM[] GetMechanismList(U_INT slotId){
			
			C_GetMechanismList proc=(C_GetMechanismList)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetMechanismList));
			
			U_INT pulCount=0;
			checkCKR( proc(slotId,null,ref pulCount));
			
			CKM[] mechanismList = new CKM[pulCount];
			
			checkCKR( proc(slotId, mechanismList,ref pulCount));
			
			return  mechanismList;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotId"></param>
		/// <param name="mechanism"></param>
		/// <returns></returns>
		public CK_MECHANISM_INFO GetMechanismInfo(U_INT slotId, CKM mechanism){
			
			C_GetMechanismInfo proc=(C_GetMechanismInfo)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetMechanismInfo));
			
			CK_MECHANISM_INFO mecInfo=new CK_MECHANISM_INFO();
			
			checkCKR(proc(slotId,mechanism,ref mecInfo) );
			
			return mecInfo;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotId"></param>
		/// <param name="pin"></param>
		/// <param name="label"></param>
		public void InitToken(U_INT slotId, string pin, string label){
			
			C_InitToken proc=(C_InitToken)DelegateUtil.GetDelegate(this.hLib,typeof(C_InitToken));

			byte[] pinBytes=System.Text.Encoding.UTF8.GetBytes(pin);
			
			byte[] labelBytes=new byte[32];
			new List<byte>(System.Text.Encoding.UTF8.GetBytes(label+new String(' ',32 ))).CopyTo(0,labelBytes,0,32);
			
			checkCKR(proc(slotId,pinBytes,(U_INT)pinBytes.Length,labelBytes));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pin"></param>
		public void InitPIN(U_INT hSession , string pin){
			
			C_InitPIN proc = (C_InitPIN)DelegateUtil.GetDelegate(this.hLib,typeof(C_InitPIN));
			
			byte[] pinBytes=System.Text.Encoding.UTF8.GetBytes(pin);
			
			checkCKR(proc(hSession,pinBytes,(U_INT)pinBytes.Length));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="oldPin"></param>
		/// <param name="newPin"></param>
		public void SetPIN (U_INT hSession, string oldPin, string newPin){
			
			C_SetPIN proc = (C_SetPIN)DelegateUtil.GetDelegate(this.hLib,typeof(C_SetPIN));
			
			byte[] oldPinBytes=System.Text.Encoding.UTF8.GetBytes(oldPin);
			byte[] newPinBytes=System.Text.Encoding.UTF8.GetBytes(newPin);
			
			checkCKR(
				proc(hSession,oldPinBytes,(U_INT)oldPinBytes.Length,newPinBytes,(U_INT)newPinBytes.Length));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotId"></param>
		/// <param name="applicationId"></param>
		/// <param name="readOnly"></param>
		/// <returns></returns>
		public U_INT OpenSession(U_INT slotId, U_INT applicationId, bool readOnly){
			
			C_OpenSession proc= (C_OpenSession)DelegateUtil.GetDelegate(this.hLib,typeof(C_OpenSession));
			
			U_INT flags=PKCS11Constants.CKF_SERIAL_SESSION| (readOnly? 0: PKCS11Constants.CKF_RW_SESSION);
			
			U_INT hSession=0;
			
			checkCKR( proc(slotId,flags, ref applicationId, IntPtr.Zero, ref hSession) );
			
			return hSession;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		public void CloseSession(U_INT hSession){
			
			C_CloseSession proc= (C_CloseSession)DelegateUtil.GetDelegate(this.hLib,typeof(C_CloseSession));
			
			checkCKR(proc(hSession));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="slotId"></param>
		public void CloseAllSessions(U_INT slotId){
			#if CDECL 
            [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute(System.Runtime.InteropServices.CallingConvention.Cdecl)]
            #endif
			C_CloseAllSessions proc= (C_CloseAllSessions)DelegateUtil.GetDelegate(this.hLib,typeof(C_CloseAllSessions));
			
			checkCKR(proc(slotId));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public CK_SESSION_INFO GetSessionInfo(U_INT hSession){
			
			C_GetSessionInfo proc= (C_GetSessionInfo)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetSessionInfo));

			CK_SESSION_INFO sessionInfo=new CK_SESSION_INFO();
			
			checkCKR(proc(hSession, ref sessionInfo));
			
			return sessionInfo;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public byte[] GetOperationState(U_INT hSession){
			
			C_GetOperationState proc= (C_GetOperationState)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetOperationState));
			
			U_INT pLen=0;
			
			checkCKR(proc(hSession, null, ref pLen));
			
			byte[] opState=new byte[pLen];
			
			checkCKR(proc(hSession, opState, ref pLen));
			
			return opState;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="opState"></param>
		/// <param name="hEncryptionKey"></param>
		/// <param name="hAuthenticationKey"></param>
		public void SetOperationState(U_INT hSession, byte[] opState, U_INT hEncryptionKey, U_INT hAuthenticationKey){
			
			C_SetOperationState proc= (C_SetOperationState)DelegateUtil.GetDelegate(this.hLib,typeof(C_SetOperationState));
			
			checkCKR ( proc(hSession, opState, (U_INT)opState.Length, hEncryptionKey, hAuthenticationKey ) );
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="userType"></param>
		/// <param name="pin"></param>
		public void Login(U_INT hSession, CKU userType, string pin){
			
			C_Login proc = (C_Login)DelegateUtil.GetDelegate(this.hLib,typeof(C_Login));
			
			byte[] pinBytes=System.Text.Encoding.UTF8.GetBytes(pin);
			
			checkCKR(proc(hSession, userType, pinBytes, (U_INT)pinBytes.Length ));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		public void Logout(U_INT hSession){
			
			C_Logout proc= (C_Logout)DelegateUtil.GetDelegate(this.hLib,typeof(C_Logout));
			
			checkCKR(proc(hSession));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="template"></param>
		/// <returns></returns>
		public U_INT CreateObject(U_INT hSession, CK_ATTRIBUTE[] template){
			
			C_CreateObject proc= (C_CreateObject)DelegateUtil.GetDelegate(this.hLib,typeof(C_CreateObject));
			
			U_INT hObj=0;
			
			checkCKR(proc(hSession,template, (U_INT)template.Length,ref hObj));
			
			return hObj;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="hObj"></param>
		public void DestroyObject(U_INT hSession, U_INT hObj){
			
			C_DestroyObject proc= (C_DestroyObject)DelegateUtil.GetDelegate(this.hLib,typeof(C_DestroyObject));
			
			checkCKR(proc.Invoke(hSession,hObj));
		}
		
		//TODO: implement C_CopyObject
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="hObj"></param>
		/// <returns></returns>
		public U_INT GetObjectSize(U_INT hSession, U_INT hObj){
			
			C_GetObjectSize proc= (C_GetObjectSize)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetObjectSize));
			
			U_INT pulSize=0;
			
			checkCKR(proc.Invoke(hSession,hObj, ref pulSize));
			
			return pulSize;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="hObj"></param>
		/// <param name="template"></param>
		/// <returns></returns>
		public CK_ATTRIBUTE[] GetAttributeValue(U_INT hSession, U_INT hObj, CK_ATTRIBUTE[] template ){
			
			C_GetAttributeValue proc= (C_GetAttributeValue)DelegateUtil.GetDelegate(this.hLib,typeof(C_GetAttributeValue));
			for(int i=0;i<template.Length;i++){
				bool needsBuffer= template[i].pValue==IntPtr.Zero;
				checkCKR(proc.Invoke(hSession,hObj, ref template[i], 1));
				if(needsBuffer&&template[i].ulValueLen>0 ){
					template[i].pValue=Marshal.AllocHGlobal((int) template[i].ulValueLen);
					checkCKR(proc.Invoke(hSession,hObj, ref template[i], 1));
				}
			}
			
			return template;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="hObj"></param>
		/// <param name="pTemplate"></param>
		public void SetAttributeValue(U_INT hSession, U_INT hObj, CK_ATTRIBUTE[] pTemplate){
			
			C_SetAttributeValue proc= (C_SetAttributeValue)DelegateUtil.GetDelegate(this.hLib,typeof(C_SetAttributeValue));
			for(int i=0;i<pTemplate.Length;i++)
				checkCKR(proc.Invoke(hSession,hObj, ref pTemplate[i], (U_INT)pTemplate.Length));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pTemplate"></param>
		public void FindObjectsInit(U_INT hSession, CK_ATTRIBUTE[] pTemplate){
			
			C_FindObjectsInit proc= (C_FindObjectsInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_FindObjectsInit));
			if(pTemplate==null || pTemplate.Length<1)
				checkCKR(proc.Invoke(hSession, null, 0));
			else
				checkCKR(proc.Invoke(hSession, pTemplate, (U_INT)pTemplate.Length));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="maxCount"></param>
		/// <returns></returns>
		public U_INT[] FindObjects(U_INT hSession, U_INT maxCount){
			
			C_FindObjects proc= (C_FindObjects)DelegateUtil.GetDelegate(this.hLib,typeof(C_FindObjects));
			
			U_INT[] maxObjs=new U_INT[maxCount];
			
			U_INT pulCount=0;
			
			/* get the objects */
			checkCKR(proc.Invoke(hSession, maxObjs,maxCount, ref pulCount));
			
			if(pulCount==maxCount){
				
				return maxObjs;
				
			}else{/*if the count of the objects is less then maxcount then handle it */
				
				U_INT[] pulObjs=new U_INT[pulCount];
				
				Array.Copy(maxObjs,pulObjs,pulObjs.Length);
				
				return pulObjs;
			}
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		public void FindObjectsFinal(U_INT hSession){
			
			C_FindObjectsFinal proc= (C_FindObjectsFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_FindObjectsFinal));
			
			checkCKR(proc.Invoke(hSession));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pMechanism"></param>
		/// <param name="hKey"></param>
		public void EncryptInit(U_INT hSession, CK_MECHANISM pMechanism, U_INT hKey){
			
			C_EncryptInit proc=(C_EncryptInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_EncryptInit));
			
			checkCKR(proc.Invoke(hSession,ref pMechanism,hKey));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pData"></param>
		/// <returns></returns>
		public byte[] Encrypt(U_INT hSession, byte[] pData){
			
			C_Encrypt proc=(C_Encrypt)DelegateUtil.GetDelegate(this.hLib,typeof(C_Encrypt));
			
			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, null, ref size));
			
			byte[] pEncryptedData=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, pEncryptedData, ref size));
			
			return pEncryptedData;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pPart"></param>
		/// <returns></returns>
		public byte[] EncryptUpdate(U_INT hSession, byte[] pPart){
			C_EncryptUpdate proc=(C_EncryptUpdate)DelegateUtil.GetDelegate(this.hLib,typeof(C_EncryptUpdate));
			
			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pPart,(U_INT)pPart.Length, null, ref size));
			
			byte[] pEncryptedData=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pPart,(U_INT)pPart.Length, pEncryptedData, ref size));
			
			return pEncryptedData;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public byte[] EncryptFinal(U_INT hSession){
			
			C_EncryptFinal proc=(C_EncryptFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_EncryptFinal));
			
			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, null, ref size));
			
			byte[] pEncryptedData=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pEncryptedData, ref size));
			
			return pEncryptedData;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pMechanism"></param>
		/// <param name="hKey"></param>
		public void DecryptInit (U_INT hSession, CK_MECHANISM pMechanism, U_INT hKey){
			
			C_DecryptInit proc=(C_DecryptInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_DecryptInit));
			
			checkCKR(proc.Invoke(hSession,ref pMechanism,hKey));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pEncryptedData"></param>
		/// <returns></returns>
		public byte[] Decrypt(U_INT hSession, byte[] pEncryptedData){
			
			C_Decrypt proc=(C_Decrypt)DelegateUtil.GetDelegate(this.hLib,typeof(C_Decrypt));

			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pEncryptedData,(U_INT)pEncryptedData.Length, null, ref size));
			
			byte[] pData=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pEncryptedData,(U_INT)pEncryptedData.Length, pData, ref size));
			
			return pData;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pEncryptedPart"></param>
		/// <returns></returns>
		public byte[] DecryptUpdate(U_INT hSession, byte[] pEncryptedPart){
			
			C_DecryptUpdate proc=(C_DecryptUpdate)DelegateUtil.GetDelegate(this.hLib,typeof(C_DecryptUpdate));

			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pEncryptedPart,(U_INT)pEncryptedPart.Length, null, ref size));
			
			byte[] pPart=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pEncryptedPart,(U_INT)pEncryptedPart.Length, pPart, ref size));
			
			return pPart;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public byte[] DecryptFinal(U_INT hSession){
			
			C_DecryptFinal proc=(C_DecryptFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_DecryptFinal));
			
			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, null, ref size));
			
			byte[] pLastPart=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pLastPart, ref size));
			
			return pLastPart;
		}
		

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pMechanism"></param>
		/// <param name="hKey"></param>
		public void DigestInit (U_INT hSession, CK_MECHANISM pMechanism){
			
			C_DigestInit proc=(C_DigestInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_DigestInit));
			
			checkCKR(proc.Invoke(hSession,ref pMechanism));
		}
		

		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pData"></param>
		/// <returns></returns>
		public byte[] Digest(U_INT hSession, byte[] pData){
			
			C_Digest proc=(C_Digest)DelegateUtil.GetDelegate(this.hLib,typeof(C_Digest));

			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, null, ref size));
			
			byte[] pDigest=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, pDigest, ref size));
			
			return pDigest;
		}

		public void DigestUpdate(U_INT hSession, byte[] pPart){
			
			C_DigestUpdate proc=(C_DigestUpdate)DelegateUtil.GetDelegate(this.hLib,typeof(C_DigestUpdate));

			checkCKR(proc.Invoke(hSession, pPart,(U_INT)pPart.Length));
			
			return ;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="hKey"></param>
		public void DigestKey(U_INT hSession, U_INT hKey){
			
			C_DigestKey proc=(C_DigestKey)DelegateUtil.GetDelegate(this.hLib,typeof(C_DigestKey));
			
			checkCKR(proc.Invoke(hSession, hKey));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public byte[] DigestFinal(U_INT hSession){
			
			C_DigestFinal proc=(C_DigestFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_DigestFinal));
			
			U_INT size=0;
			
			checkCKR(proc.Invoke(hSession, null,ref size));
			
			byte[] pDigest=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pDigest,ref size));
			
			return pDigest;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pMechanism"></param>
		/// <param name="hKey"></param>
		public void SignInit (U_INT hSession, CK_MECHANISM pMechanism, U_INT hKey){
			C_SignInit proc=(C_SignInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_SignInit));
			
			checkCKR(proc.Invoke(hSession,ref pMechanism,hKey));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pData"></param>
		/// <returns></returns>
		public byte[] Sign(U_INT hSession, byte[] pData){
			
			C_Sign proc=(C_Sign)DelegateUtil.GetDelegate(this.hLib,typeof(C_Sign));

			U_INT size = 0;
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, null, ref size));
			
			byte[] pSignature=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, pSignature, ref size));
			
			return pSignature;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pPart"></param>
		public void SignUpdate(U_INT hSession, byte[] pPart){
			
			C_SignUpdate proc=(C_SignUpdate)DelegateUtil.GetDelegate(this.hLib,typeof(C_SignUpdate));

			checkCKR(proc.Invoke(hSession, pPart,(U_INT)pPart.Length));
			
			return ;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public byte[] SignFinal(U_INT hSession){
			
			C_SignFinal proc=(C_SignFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_SignFinal));
			
			U_INT size=0;
			
			checkCKR(proc.Invoke(hSession, null,ref size));
			
			byte[] pSignature=new byte[size];
			
			checkCKR(proc.Invoke(hSession, pSignature,ref size));
			
			return pSignature;
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pMechanism"></param>
		/// <param name="hKey"></param>
		public void VerifyInit (U_INT hSession, CK_MECHANISM pMechanism, U_INT hKey){
			C_VerifyInit proc=(C_VerifyInit)DelegateUtil.GetDelegate(this.hLib,typeof(C_VerifyInit));
			
			checkCKR(proc.Invoke(hSession,ref pMechanism,hKey));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <param name="pData"></param>
		/// <param name="signature"></param>
		public void Verify(U_INT hSession, byte[] pData, byte[] signature){
			
			C_Verify proc=(C_Verify)DelegateUtil.GetDelegate(this.hLib,typeof(C_Verify));

			checkCKR(proc.Invoke(hSession, pData,(U_INT)pData.Length, signature, (U_INT)signature.Length));
		}
		
		
		public void VerifyUpdate(U_INT hSession, byte[] pPart){
			
			C_VerifyUpdate proc=(C_VerifyUpdate)DelegateUtil.GetDelegate(this.hLib,typeof(C_VerifyUpdate));

			checkCKR(proc.Invoke(hSession, pPart,(U_INT)pPart.Length));
		}
		
		/// <summary>
		/// 
		/// </summary>
		/// <param name="hSession"></param>
		/// <returns></returns>
		public void VerifyFinal(U_INT hSession, byte[] signature){
			
			C_VerifyFinal proc=(C_VerifyFinal)DelegateUtil.GetDelegate(this.hLib,typeof(C_VerifyFinal));
			
			checkCKR(proc.Invoke(hSession, signature, (U_INT)signature.Length ));
		}
		
		public U_INT GenerateKey(U_INT hSession, CK_MECHANISM mech, CK_ATTRIBUTE[] template){
			C_GenerateKey proc=(C_GenerateKey)DelegateUtil.GetDelegate(this.hLib,typeof(C_GenerateKey));
			U_INT hKey=0;
			checkCKR(proc.Invoke(hSession, ref mech, template, (U_INT)template.Length, ref hKey));
			return hKey;
		}
		
		public KeyPairHandler GenerateKeyPair(U_INT hSession, CK_MECHANISM mech, CK_ATTRIBUTE[] pubKeyTemplate,CK_ATTRIBUTE[] privKeyTemplate){
			C_GenerateKeyPair proc=(C_GenerateKeyPair)DelegateUtil.GetDelegate(this.hLib,typeof(C_GenerateKeyPair));
			
			KeyPairHandler kp=new KeyPairHandler();			
			checkCKR(proc.Invoke(hSession, ref mech,
			                     pubKeyTemplate, (U_INT)pubKeyTemplate.Length,
			                     privKeyTemplate, (U_INT)privKeyTemplate.Length,
			                     ref kp.hPublicKey,
			                     ref kp.hPrivateKey
			                    )
			        );
			return kp;
		}
		
		protected void checkCKR(CKR retVal)
        {
            if (retVal != CKR.OK)
            {
                throw new TokenException(retVal);
            }
		}
	}
}