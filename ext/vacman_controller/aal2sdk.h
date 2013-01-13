/*========================================================================*/
/*              ADVANCED AUTHENTICATION LEVEL 2 LIBRARIES                 */
/*------------------------------------------------------------------------*/
/* Version      : 3.10.1                                                   */
/* Environment  : Multi-Platform                                          */
/* Date created : 27 Jun 1999                                             */
/* Component Id : AAL2SDK.H                                               */
/* Description  : Kernel Functions Prototypes                             */
/*                                                                        */
/* Copyright(c) 2009 VASCO Data Security, Inc, VASCO Data Security        */
/* International GmbH. All rights reserved. VASCO(R), Vacman(R),          */
/* IDENTIKEY(R), aXsGUARD(TM), DIGIPASS(R), and "VASCO 'V' logo"(R) are   */
/* registered or unregistered trademarks of VASCO Data Security, Inc.     */
/* and/or VASCO Data Security International GmbH. in the U.S. and other   */
/* countries.                                                             */
/*                                                                        */
/*------------------------------------------------------------------------*/
/*                     MAINTENANCE HISTORY TABLE                          */
/*------------------------------------------------------------------------*/
/* DD/MM/YYYY | V.R.M  |  Reason   |            Comments                  */
/*------------+--------+-----------+--------------------------------------*/
/* 21/02/2002 | 3.2.3  |           | Return Host Code Support             */
/*            |        |           | AES Support                          */
/* 31/05/2002 | 3.3.0  |           | Static Password Support              */
/*            |        |           | MD5 Support                          */
/* 23/09/2002 | 3.3.1  |           | Low Drift Adjustment Support for     */
/*            |        |           | time based algorithm                 */
/* 17/10/2002 | 3.3.2  |           | Blob Synchronisation Function for    */
/*            |        |           | time based algorithm                 */
/* 22/10/2002 |3.3.2.1 |           | The AAL2DPXInitEx function accepts   */
/*            |        |           | the InitKey with ODD parity or not   */
/* 04/11/2002 |3.3.2.2 | Bug Fix   | DPInfo->LastTimeshift Format was  not*/
/*            |        |           | expressed correctly for negative value*/
/* 13/12/2002 |3.3.2.3 | Bug Fix   | DP_S + Extended Signature            */
/* 28/01/2003 |3.3.2.4 |           | New function AAL2GetTokenSingleInfo  */
/* 07/02/2003 |3.3.2.5 | Update    | AAL2GenerateChallengeEx              */
/*            |        |           | Message has been  shorten            */
/*            |        |           | DF counter was increased             */
/* 11/02/2003 |3.3.2.6 | Bug Fix   | AAL2GetTokenInfoEx                   */
/*            |        |           | USE_COUNT, LAST_TIME_SHIFT,          */
/*            |        |           | PIN_MIN_LEN and PIN_LEN information  */
/*            |        |           | were not correctly processed         */
/* 20/02/2003 |3.3.2.7 | Bug Fix   | AAL2Unlock                           */
/*            |        |           | returned wrong Unlock code if        */
/*            |        |           | Unlock Challenge was right padded    */
/* 20/02/2003 |3.3.2.8 | Bug Fix   | DPX Import supports multiple Sessions*/
/*            |        |           | in aDPX file                         */
/*            |        |           | Unlock Challenge was right padded    */
/* 03/03/2003 |3.3.2.8 | Bug Fix   | 0 was not accepted as a min len for  */
/*            |        |           | a data fiefd                         */
/* 05/03/2003 |3.3.3.0 | New       | AAL2GenUnlockAuthCode                */
/*            |        | Functions | AAL2AuthorizeUnlock                  */
/* 22/04/2003 |3.3.3.1 | Bug Fix   | When DPX contains multiple sections  */
/*            |        |           | Token included in the first          */
/*            |        |           | section were not correctly imported  */
/* 10/06/2003 |3.4.0.0 |Enhancement| HSM Support                          */
/* 10/06/2003 |3.4.0.1 |Enhancement| Storage derivation key support       */
/* 19/06/2003 |3.4.0.1 |Enhancement| challenge/response replay attack     */
/*            |        |           | for time base algo                   */
/* 30/07/2003 |3.4.0.3 |Bug Fix    | Checkchallenge function fix          */
/* 30/07/2003 |3.4.0.3 |Bug Fix    | Reset and Dynamic PIN change were    */
/*            |        |           | not working                          */
/* 31/07/2003 |3.4.0.3 |Bug Fix    | Full Triple DES Support 0x2000000L   */
/* 12/11/2003 |3.4.0.4 |Bug Fix    | Blob Compatibility issue LITTLE BIG  */
/*            |        |           | ENDIAN IVLEFT                        */
/* 17/02/2004 |3.4.0.4 |Bug Fix    | Improved Param Checks in export fns  */
/* 03/03/2004 |3.4.0.4 |Bug Fix    | Unlock fn: response checksum was not */
/*            |        |           | supported                            */
/* 03/03/2004 |3.4.0.4 |Bug Fix    | SN Check digit calculation was wrong */
/*            |        |           | in fct AAL2CINIT_AProcess            */
/* 15/03/2004 |3.4.0.4 |Bug Fix    | Rename DPSDK to DASSDK               */
/* 23/03/2004 |3.4.0.4 |Restructure| include OS/390 names directly        */
/* 10/06/2004 |3.4.0.4 |Enhancement| Cater for Solaris 64 bit compilation */
/* 11/06/2004 |3.5.0.0 |Enhancement| Virtual Token Support                */
/* 13/07/2004 |3.5.0.0 |Enhancement| Code Replay is detected after a reset*/
/* 07/12/2004 |3.5.0.1 |Bug Fix    | DEC 2 Response format                */
/* 20/01/2005 |3.5.0.2 |Enhancement| New Property Supported by the        */
/*            |        |           | AAL2SetTokenProperty: PIN_ENABLED    */
/*            |        |           |                     : PIN_CH_FORCED  */
/*            |        |           |                     : ERROR_COUNT    */
/* 23/03/2005 |3.5.0.3 |Enhancement| Dynamic Windows Support              */
/* 30/03/2005 |3.5.0.4 |Bug Fix    | Used Time Window for Dynamic was wrng*/
/* 30/03/2005 |3.5.0.4 |Bug Fix    | Return Code=1 for various errors fix */
/* 04/05/2005 |3.5.0.7 |Bug Fix    | some #defines in aal2defs.h needed   */
/*            |        |           | here for public use                  */
/* 10/10/2005 |3.5.0.11|Bug Fix    | Password length in mshash functions  */
/* 10/11/2005 |3.5.4.1 |Enhancement| HSM functionality                    */
/* 19/12/2005 |3.6.0.0 |Enhancement| EMV functionality                    */
/* 04/01/2006 |3.6.0.2 |Enhancement| modification of GenEMVBlob           */
/* 13/01/2006 |3.6.1.0 |Enhancement| New function - AAL2GenTestPassword   */
/* 10/02/2006 |3.6.3.0 |Enhancement| DP4WEb Activation Code Generation    */
/* 20/02/2006 |3.6.4.0 |Enhancement| Alpha-numeric challenge support      */
/* 02/05/2006 |3.6.4.1 |Add        | AAL2SetSession                       */
/* 24/02/2006 |3.6.5.0 |Enhancement| Offline Authentication               */
/* 20/07/2006 |3.6.8.0 |Merge      | CTVS + Off + PKCS11 + QA             */
/* 16/08/2006 |3.6.8.0 |Add        | AAl2GetTokenProperty                 */
/* 21/08/2006 |3.6.9.0 |Enhancement| Versions Merge + Enhancement DP4WEB  */
/*            |        |Enhancement| + Enhancement EMV                    */
/* 04/09/2006 |3.6.10.0|Enhancement| Add support SyncTokenAndHost in HSM  */
/* 04/09/2006 |3.6.10.0|Enhancement| Double Length Key support            */
/* 28/09/2006 |3.6.10.1|Enhancement| Add new CTVS Properties to           */
/*            |        |           | AAL2GetTokenInfoEx                   */
/* 02/10/2006 |3.6.10.1|Enhancement| Union delete in TKey structure       */
/* 18/10/2006 |3.6.11.0|Enhancement| Add support for Luna HSM             */
/* 24/10/2006 |3.7.0.0 |Enhancement| Support SYNC_DIGIT with DEC2 response*/
/* 20/11/2006 |3.7.0.1 |Enhancement| DP_ALGO in combination with Host code*/
/*            |        |           | AND length hostcode + length response*/
/*            |        |           | > 14                                 */
/* 14/12/2006 |3.7.1.0 |Enhancement| Enhancement DP4WEB                   */
/* 17/01/2007 |3.7.2.0 |Enhancement| HSM functionality                    */
/*            |        |           | Support netHSM Big Endian (PowerPC)  */
/* 19/01/2007 |3.7.2.1 |Bug Fix    | Unique key name for tmp key          */
/* 01/02/2007 |3.7.2.2 |Bug Fix    | Replace // commentary by */ /* */  /**/
/* 05/02/2007 |3.7.3.0 |Enhancement| Add Matrix Card Support Functions    */
/* 07/02/2007 |3.7.3.0 |Bug Fix    | MD5Calculate -> vds_MD5Calculate     */
/* 06/02/2007 |3.7.3.1 |Add        |AAL2VerifyAll                         */
/* 06/02/2007 |3.7.3.1 |Add        |AAL2DPXGetAllToken                    */
/* 09/03/2007 |3.7.3.2 |Name Fix   |AAL2DPXGetAllToken->AAL2DPXGetTokenBlobs*/
/* 16/03/2007 |3.7.5.0 |Bug Fix    | Bug in AAL2GetTokenInfoEx            */
/*            |        |           | with BIG_ENDIAN                      */
/* 27/04/2007 |3.7.5.1 |Bug Fix    | Bug Fix in MX Card                   */
/* 03/05/2007 |3.7.5.2 |Enhancement| Modify AAL2SyncTokenAndHostHSM for JP*/
/* 03/05/2007 |3.7.5.2 |Bug Fix    | ProductionTimeWindow value harcoded  */
/* 14/05/2007 |3.7.5.6 |Enhancement| AAL2DPXGetStaticVector               */
/* 05/06/2007 |3.7.6.1 |Bug Fix    | support of token drift > 4s/day      */
/* 12/06/2007 |3.7.6.2 |Bug Fix    | DP_ALGO response and host key length */
/* 12/06/2007 |3.7.6.2 |Bug Fix    | Bug Fix in AAL2DPXGetStaticVector    */
/* 22/06/2007 |3.7.6.3 |Bug Fix    | Bug Fix in AAL2MXGenAuthChar         */
/* 06/08/2007 |3.7.7.0 |Bug Fix    | Bug Fix in AAL2VerifySignature       */
/* 06/08/2007 |3.7.7.0 |Enhancement| Add integer output format for        */
/*            |        |           | LAST_TIME_USED in AAL2GetTokenInfoEx */
/* 03/09/2007 |3.7.7.1 |Enhancement| Odd security level support in MX     */
/* 20/08/2007 |3.7.8.0 |Bug Fix    | Buffer overflow fix in               */
/*            |        |           | AAL2GetTokenInfoEx                   */
/* 11/09/2007 |3.7.8.0 |Enhancement| AES support in PKCS11 (except THALES)*/
/* 05/10/2007 |3.7.8.0 |Enhancement| Support CheckChallenge=1 with null   */
/*            |        |           | length challenge for MM appli        */
/* 05/10/2007 |3.7.8.0 |Bug Fix    | Fix for memory leak issue            */
/* 09/10/2007 |3.7.9.0 |Enhancement| Added LAST_TIME_USED support in      */
/*            |        |           | AAL2SetTokenProperty                 */
/* 23/10/2007 |3.7.9.1 |Enhancement| Add AAL2SyncTokenBlobEx() function   */
/* 23/10/2007 |3.7.9.1 |Enhancement| Set the Event Synchronisation digit  */
/* 23/10/2007 |3.7.9.1 |Enhancement| Support of discrete Sync Window      */
/* 24/10/2007 |3.7.9.3 |Enhancement| Encrypted Static Password Support    */
/* 07/11/2007 |3.7.9.6 |Enhancement| AAL2SyncTokenAndHost no more         */
/*            |        |           | limitation in TIME + EVENT BASED     */
/* 12/11/2007 |3.7.9.7 |Enhancement| Add VDP for HSM                      */
/* 13/11/2007 |3.7.9.7 |BugFix     | Add Missing Low Pass Filter for      */
/*            |        |           | Signature                            */
/* 12/11/2007 |3.7.9.9 |Bug fix    | Challenge concatenated fix           */
/* 27/11/2007 |3.7.9.10|Enhancement| Remove low pass filter limitation    */
/*            |        |           | in AAL2SyncTokenAndHost              */
/* 19/12/2007 |3.7.10.1|Enhancement|Add AAL2GetTokenSingleInfoHSM         */
/* 19/12/2007 |3.7.10.1|Enhancement|Add AAL2GetTokenInfoExHSM             */
/* 19/12/2007 |3.7.10.1|Enhancement| Support of RHC up to 16 digits       */
/* 10/01/2008 |3.7.10.3|Enhancement| Support Alphanumeric Output for CTVS */
/* 10/12/2007 |3.7.10.3|Enhancement| Support GenEMVBlob and GenEMVCAP CTVS*/
/*            |        |           | mode1 mode2 mode3 in CTVS HSM version*/
/* 10/01/2008 |3.7.10.3|Enhancement| KCV in TKey Structure for VC CTVS HSM*/
/* 10/01/2008 |3.7.10.3|Enhancement| IPB is now Mandatory in VC CTVS      */
/* 10/01/2008 |3.7.10.4|Enhancement| Support Zenginkyo Card in VC CTVS    */
/* 23/01/2008 |3.7.10.5|Enhancement| Add AAL2GenEMVBlobEx in VC CTVS      */
/*            |        |           | AAL2GenEMVBlob deprecated            */
/* 23/01/2008 |3.7.10.5|Enhancement| Add AAL2GenGenEMVBlobExCmd and       */
/*            |        |           | Add AAL2ProcGenEMVBlobExRpl in VC CTVS*/
/* 28/01/2008 |3.7.10.6|Bug Fix    | Host Code Buffer max size increment  */
/*            |        |           | to 16                                */
/* 29/01/2008 |3.7.10.7|Bug Fix    |No error code was returned for invalid*/
/*            |        |           |property in AAL2GetTokenSingleInfo(gte)*/
/* 11/02/2008 |3.7.10.8|Bug Fix    | EMV IAF flag was not handled correctly*/
/* 12/02/2008 |3.7.10.8|Bug Fix    | Ignore IAF flag for ZENGINKYO        */
/* 15/02/2008 |3.7.10.9|Enhancement| AAL2GenEMVBlob removed from VC CTVS  */
/* 20/02/2008 |3.7.10.11|Bug Fix   | Fix CDOL checks - 0'd and valued tags*/
/* 20/02/2008 |3.7.10.11|Bug Fix   | Fix ATC iteration - Add ATC Bit mask check*/
/* 31/03/2008 |3.7.11.1|Enhance    |Validation with Enhanced Security     */
/*            |        |           |Support (AAL2VerifyPasswordEs,        */
/*            |        |           |AAL2VerifySignatureEs)                */
/* 30/04/2008 |3.7.11.2|Enhancement|Support TOTP (OATH Time Based)        */
/* 05/05/2008 |3.7.11.3|Enhancement|CAP E Support in CTVS                 */
/* 05/05/2008 |3.7.11.3|Bug Fix    |Bug Fix in AAL2GenActivation Code on  */
/*            |        |           |Alea and HS longer than 512 characters*/
/* 05/05/2008 |3.7.11.3|Bug Fix    |Buf Fix in emvl0DecDigitsToByteArray  */
/*            |        |           |on 20 digits secure code              */
/* 05/05/2008 |3.7.11.3|Bug Fix    |Default UKIS CDOL include Visa Data   */
/* 15/05/2008 |3.7.12.4|Enhancement|Software Migration Support            */
/*            |        |           |(AAL2MigrateBlob)                     */
/* 06/06/2008 |3.8.0.0 |Enhancement|Secure Code Generation no more        */
/*            |        |           |permited with VC for CTVS with HSM    */
/*            |        |           |(GenEMVCAPMode1, Mode2, Mode3)        */
/* 20/06/2008 |3.8.0.1 |Bug Fix    |Possible incorrect Integer value with */
/*            |        |           |GetTokenProperty in java              */
/* 20/06/2008 |3.8.0.2 |Bug Fix    |Type cast to avoid compile warnings   */
/* 01/07/2008 |3.8.0.2 |Bug Fix    |Null KP with emvl1VerifyEMVSecureCode */
/* 01/07/2008 |3.8.0.2 |BugFix     |Avoid CODE REPLAY error in CTVS       */
/*            |        |           |if card ATC = server ATC +            */
/*            |        |           |(ATC Mask size * n) with n>0          */
/* 22/07/2008 |3.8.1.0 |Enhancement|New Event Window management for CTVS  */
/* 05/09/2008 |3.8.1.1 |BugFix     |Using synchronized CID and IAD when   */
/*            |        |           |formatting message.                   */
/* 15/09/2008 |3.8.1.1 |Bug Fix    |Remove range limitation for DV and SDK*/
/*            |        |           |in AAL2MigrateBlob                    */
/* 16/09/2008 |3.8.1.1 |Bug Fix    |Fixed Signature Generation (Virtual   */
/*            |        |           |Token) to use Host clock rather       */
/*            |        |           |than HSM clock                        */
/* 16/09/2008 |3.8.1.1 |Bug Fix    |Avoid crash if using AAL2VerifySignature*/
/*            |        |           |rather than AAL2VerifySignatureEx     */
/*            |        |           |with an Host code len > 4             */
/* 16/09/2008 |3.8.1.1 |Enhancement|Enhance des_pseudo_random for         */
/*            |        |           |reentrancy support                    */
/* 25/09/2008 |3.8.1.2 |BugFix     |Fixed conversion uint32 -> ASCII for  */
/*            |        |           |Banksys                               */
/* 09/10/2008 |3.8.1.2 |Bug Fix    |Wrong timestep property display in TOTP*/
/* 03/11/2008 |3.8.1.3 |Bug Fix    |Fix after citibank report             */
/* 18/11/2008 |3.8.1.4 |Bug Fix    |Bad ReturnHostcode Buffer allocation  */
/*            |        |           |for AAL2ProcVerifyPasswordReply and   */
/*            |        |           |AAL2ProcVerifySignatureReply in JNI   */
/*            |        |           |Wrapper                               */
/* 28/11/2008 |3.8.2.0 |Bug Fix    |Offline Signature validation fails    */
/*            |        |           |with Event Sync Digit                 */
/* 04/12/2008 |3.8.2.0 |Enhancement|Add KernelParms() constructor in Java */
/* 04/12/2008 |3.8.2.0 |Enhancement|Functions dedicated for VC Offline    */
/*            |        |           |module are now exported by default    */
/*            |        |           |(AAL2GenHashDataBlock, AAL2SyncStateData*/
/*            |        |           |and AAL2GetStateDataBlock)            */
/* 16/12/2008 |3.8.2.0 |Bug Fix    |Serial Number attribute is valued in  */
/*            |        |           |Digipass object after a call to       */
/*            |        |           |AAL2DPXGetTokenBlobs in java          */
/* 02/12/2008 |3.8.3.0 |Bug Fix    |Improve some Input/Output parameters  */
/*            |        |           |validity in cmd/reply functions.(HSM) */
/* 19/12/2008 |3.8.3.0 |Bug Fix    |Check serial number pointer and length*/
/*            |        |           |when generate GenEMVBlob commamd.(HSM)*/
/* 12/01/2009 |3.8.3.0 |Bug Fix    |Work with size of DataField array in  */
/*            |        |           |Java wrapper in conjonction with the  */
/*            |        |           |input parameter value.                */
/* 15/01/2009 |3.8.3.0 |Bug Fix    |Use AES algo for AuthorizeUnlock code */
/*            |        |           |only for unlock V2 procedure.         */
/* 19/01/2009 |3.8.3.0 |Bug Fix    |Fixed Signature Generation (Virtual Token) */
/*            |        |           |Use Host clock rather than HSM clock  */
/* 20/01/2009 |3.8.3.0 |bug Fix    |Initialize Found member of TTLVItem   */
/*            |        |           |to false before calling DecodeTLV     */
/* 04/02/2009 |3.9.0.0 |Enhancement|Post Increment ATC to generate with ATC+1 */
/* 25/02/2009 |3.9.0.0 |Bug Fix    |AAL2GenHashDataBlock takes into account*/
/*            |        |           |the Last Time Shift of DIGIPASS time Based*/
/* 06/03/2009 |3.9.0.0 |Bug Fix    |Add null terminated character for     */
/*            |        |           |returned MXChallenge                  */
/* 06/03/2009 |3.9.0.0 |Bug Fix    |Add support of CheckChallenge = 2     */
/*            |        |           |with MXCards                          */
/* 18/03/2009 |3.9.0.0 |Bug Fix    |Missing check to reject blob encrypted*/
/*            |        |           |under HSM level Transport Key in      */
/*            |        |           |AAL2Unlock                            */
/* 18/03/2009 |3.9.0.0 |Bug Fix    |Replace ifdef _HSM_FM clause by _HSM  */
/*            |        |           |in AAL2VerifyEsHSM                    */
/* 18/03/2009 |3.9.0.0 |Bug Fix    |BugFixes in AAL2SyncTokenAndHostHSM to*/
/*            |        |           |detect CheckInactiveDays, Increment   */
/*            |        |           |error counter in case of failure, event*/
/*            |        |           |based tokens bugfix                   */
/* 24/03/2009 |3.9.0.0 |Enhancement|Adding AAL2verifyWIN feature for Java */
/*            |        |           |Wrapper                               */
/* 17/04/2009 |3.9.0.3 |Enhancement|Adding AAL2verifyWIN feature for .NET */
/*            |        |           |Wrapper                               */
/* 24/04/2009 |3.9.0.4 |Bug Fix    |Fixed HSM encryption key migration    */
/*            |        |           |for 3DES blob imported with VC older  */
/*            |        |           |than 3.6.9.                           */
/* 04/05/2009 |3.9.0.5 |Bug Fix    |Endianness conversion issue with      */
/*            |        |           |big-endian HSM                        */
/* 22/06/2009 |3.9.0.6 |Enhancement|Modification to ignore                */
/*            |        |           |TW_DYNAMIC_WINDOWS if using SW_DISCRETE*/
/* 31/08/2009 |3.9.0.7 |Bug Fix    |In AAL2GenHashDataBlock, Last Time Shift*/
/*            |        |           |Correction must be done before round to */
/*            |        |           |TimeStep                              */
/* 04/09/2009 |3.9.1.0 |Enhancement|Strong Host Code authentication       */
/* 07/09/2009 |3.9.1.0 |Enhancement|In AAL2GenHashDataBlock, Maximum number*/
/*            |        |           |of event hashes is modified from 500 to*/
/*            |        |           |3000                                  */
/* 24/09/2009 |3.9.1.0 |Bug Fix    |Fix in AAL2VerifyWin to accept up to  */
/*            |        |           |255 bytes for the CHAP challenge      */
/* 06/11/2009 |3.9.1.1 |Bug Fix    |Store SignatureEvent in LastTimeShift  */
/*            |        |           |only for Event based only appli.       */
/* 09/11/2009 |3.9.1.1 |Bug Fix    |Fix for blobs synchronization with    */
/*            |        |           |different TimeStep or different profile*/
/* 10/11/2009 |3.9.2.0 |Enhancement|Support CTVS with HSM provisionning   */
/* 10/11/2009 |3.9.2.0 |Enhancement|Add AAL2GenCheckIMKBlobCmd &          */
/*            |        |           |AAL2ProcCheckIMKBlobRpl in VC CTVS    */
/* 10/11/2009 |3.9.2.0 |Enhancement|AAL2GenGenEMVBlobExCmd &              */
/*            |        |           |AAL2ProcGenEMVBlobExRpl are replaced  */
/*            |        |           |by AAL2GenEMVBlobEx  in VC CTVS       */
/* 10/11/2009 |3.9.2.0 |Enhancement|Add IMK_LABEL + KCV_TYPE + KCV_VALUE  */
/*            |        |           | support in AAL2GetTokenProperty (PDU)*/
/* 23/12/2009 |3.10.0.0|Change     |Use GetTimeStep function each time    */
/*            |        |           |we need to retrieve timeStep (Process */
/*            |        |           |OATH_ALGO and easier maintainability) */
/* 23/12/2010 |3.10.0.0|Change     |AAL2DPXGetTokenBlobsHSM: appli_count  */
/*            |        |           |is updated before return (appli_count */
/*            |        |           |used only as output parameter)        */
/* 06/01/2010 |3.10.0.0|Bug Fix    |EMV TDS fields limited to 10 digits   */
/*            |        |           |according to the specifications.      */
/* 06/01/2010 |3.10.0.0|Enhancement|AAL2SyncTokenBlobs: Static PIN Synchro*/
/* 12/01/2010 |3.10.0.0|Enhancement|Support of DPSoft with HSM            */
/* 25/01/10   |3.10.0.0|Bug Fix    |EBCDIC conversion in JNI interface    */
/*            |        |           |for AAL2GenGenerateChallengeCmd API   */
/* 26/01/2010 |3.10.0.0|Bug Fix    |Increase message size for concatenated*/
/*            |        |           |data fields                           */
/* 08/02/2010 |3.10.0.0|Bug Fix    |Fixed list of unsupported data fields */
/*            |        |           |characters on EBCDIC platform         */
/* 08/02/2010 |3.10.0.0|Bug Fix    |Fixed EBCDIC Conversion for the       */
/*            |        |           |Datafields in AAL2VerifySignatureEs   */
/* 08/02/2010 |3.10.0.0|Bug Fix    |Check invalid characters for the      */
/*            |        |           |Datafields in AAL2VerifySignatureEs   */
/* 19/02/2010 |3.10.0.0|Bug Fix    |The CHAL2_USED forced flag is no more */
/*            |        |           |done during MITMA Challenge generation*/
/* 19/02/2010 |3.10.0.0|Bug Fix    |In case of Enhanced security, the     */
/*            |        |           |authentication is rejected for DIGIPASS*/
/*            |        |           |with neither CHAL1_USED nor CHAL2_USED*/
/*            |        |           |if a ServerPublicKey is used or if the*/
/*            |        |           |datafields are compressed             */
/* 10/03/2010 |3.10.0.0|Enhancement|Support of DPSoft with HSM            */
/* 10/03/2010 |3.10.0  |Change     |QA index selection refactoring        */
/* 10/03/2010 |3.10.0  |Bug Fix    |In AAL2GenQAKey, check if number of   */
/*            |        |           |QAIndex matches number of QAHash      */
/* 10/03/2010 |3.10.0.0|Enhance    |New STRONG_HOST_CODE_APP boolean      */
/*            |        |           |property for Strong Host Code appli.  */
/* 15/03/2010 |3.10.0.0|Bug Fix    |Fix initial vectors conversion from   */
/*            |        |           |DPX app field to DIGIPASS data.       */
/*            |        |           |Must be set with '0' instead of NULL  */
/*            |        |           |when fields are not present in DPX.   */
/* 09/04/2010 |3.10.0.0|Enhancement|Change TokenStatus synchronization    */
/*            |        |           |between 2 blobs with the same SN and  */
/*            |        |           |Appli name                            */
/* 09/04/2010 |3.10.0.0|Bug Fix    |Fix to avoid issue of KCV_VALUE       */
/*            |        |           |property incorrectly returned with    */
/*            |        |           |AAL2GenTokenInfoEx                    */
/* 12/04/2010 |3.10.0.0|Enhancement|Compute UAC using 3DES algo if        */
/*            |        |           |Unlock V2 appli is 3DES               */
/* 19/04/2010 |3.10.0.0|Enhancement|Support of Event Counter Synchronisation*/
/*            |        |           |in case of DP Soft Reactivation       */
/*            |        |           |New functions:                        */
/*            |        |           | - AAL2GenActivationCodeXErc          */
/*            |        |           | - AAL2GenActivationCodeXErcHSM       */
/*            |        |           | - AAL2GenGenActivationCodeXErcCmd    */
/*            |        |           | - AAL2ProcGenActivationCodeXErcRpl   */
/* 05/05/2010 |3.10.0.0|Bug Fix    |Fix for memory leak issue on JNI      */
/*            |        |           |  wrapper when using GenActivationCode*/
/*            |        |           |  Java function                       */
/* 14/05/2010 |3.10.0.0|Change     |Backup Virtual DIGIPASS refactoring   */
/* 08/07/2010 |3.10.0.1|Bug Fix    |Support Application using Concatenated*/
/*            |        |           |Datafields with null INPUT_FILL2 filler*/
/* 27/07/2010 |3.10.0.1|Bug Fix    |Challenge/Response now supported for  */
/*            |        |           |first application with                */
/*            |        |           |AAL2GenActivationCodeXErc             */
/* 23/09/2010 |3.10.0.1|Enhancement|DES/3DES performance enhancement      */
/* 07/10/2010 |3.10.0.3|Fix        |Fix for Backup VDP enabled on DP4mobile*/
/*            |        |           |application using SW_DISCRETE flag    */
/* 07/10/2010 |3.10.0.3|Fix        |AAL2VerifySignatureEs:                */
/*            |        |           |Fix to support EBCDIC platforms.      */
/* 11/10/2010 |3.10.1.0|Enhancement|Add for HSM DOT NET Wrapper           */
/*            |        |           |AAL2GenGenActivationCodeXErcExCmd     */
/*            |        |           |AAL2ProcGenActivationCodeXErcExRpl    */
/* 13/10/2010 |3.10.1.0|Fix        |In JNI functions, add some missing    */
/*            |        |           |calls to the java wrapper function    */
/*            |        |           |which set the return code             */
/* 14/10/2010 |3.10.1.0|Enhancement|New CODE_WORD and AUTH_MODE properties*/
/*            |        |           |available in AAL2GetTokenProperty and */
/*            |        |           |AAL2GetTokenInfoEx                    */
/* 14/10/2010 |3.10.1.0|Enhancement|Extended ASCII and EBCDIC Character   */
/*            |        |           |Set for DP735.                        */
/* 14/10/2010 |3.10.1.0|Fix        |Reset DIGIPASS data flag to reflect   */
/*            |        |           |changes when blob is no more encrypted*/
/*            |        |           |with a derive vector                  */
/* 18/10/2010 |3.10.1.0|Fix        |Do not allow to generate a signature  */
/*            |        |           |on a virtual backup token             */
/* 21/10/2010 |3.10.1.0|Fix        |Fix for disabling applications with   */
/*            |        |           |no virtual token configuration        */
/* 07/11/2010 |3.10.1.0|Change     |Backup Virtual DIGIPASS modification  */
/*            |        |           |with time step = 32s or 36s depending */
/*            |        |           |of the primary application            */
/* 07/11/2010 |3.10.1.0|Fix        |Limit CurrentErrorCount to 0x7FFF.    */
/*            |        |           |In DPInfo the value is capped to 999. */
/* 07/11/2010 |3.10.1.0|Fix        |Limit UseCount to 0x7FFFFFF for DP app*/
/*            |        |           |and 0x7FFF for EMV app.               */
/*            |        |           |In DPInfo the value is capped to      */
/*            |        |           |999999 for DP app (6 digits max).     */
/* 10/11/2010 |3.10.1.0|Enhancement|Enhance challenge generation random   */
/*            |        |           |distribution                          */
/* 15/11/2010 |3.10.1.0|Fix        |EMV blob UseCount and ErrorCounter    */
/*            |        |           |are no more incremented in Secure Code*/
/*            |        |           |generation, those counters are related*/
/*            |        |           |to validation                         */
/*========================================================================*/

#ifndef AAL2SDK_H
  #define AAL2SDK_H 1

  #if defined(__MVS__)
    #ifndef _OEMVS
      #pragma map(AAL2ResetTokenInfo, "AA2VRTI")
      #pragma map(AAL2GetTokenInfo, "AA2VGTI")
      #pragma map(AAL2DP500Test, "AA2V500")
      #pragma map(AAL2VerifyAll, "AA2VVAL")
      #pragma map(AAL2VerifyAllEs, "AA2VVALS")
      #pragma map(AAL2VerifyAllEsEx, "AA2VALSX")
      #pragma map(AAL2VerifyAllHSM, "AA2VVALH")
      #pragma map(AAL2VerifyAllEsHSM, "AA2VVAHS")
      #pragma map(AAL2VerifyPassword, "AA2VVPD")
      #pragma map(AAL2VerifyPasswordEx, "AA2VVPDE")
      #pragma map(AAL2VerifyPasswordEs, "AA2VVPDS")
      #pragma map(AAL2VerifyPasswordHSM, "AA2VVPDH")
      #pragma map(AAL2VerifyPasswordEsHSM, "AA2VVPHS")
      #pragma map(AAL2VerifyPasswordHash, "AA2VVHSH")
      #pragma map(AAL2VerifySignature, "AA2VVSG")
      #pragma map(AAL2VerifySignatureEx, "AA2VVSGE")
      #pragma map(AAL2VerifySignatureEs, "AA2VVSGS")
      #pragma map(AAL2VerifySignatureEsEx, "AA2VSGSX")
      #pragma map(AAL2VerifySignatureHSM, "AA2VVSGH")
      #pragma map(AAL2VerifySignatureEsHSM, "AA2VVSHS")
      #pragma map(AAL2GenerateChallenge, "AA2VGCL")
      #pragma map(AAL2GenerateChallengeEx, "AA2VGCE")
      #pragma map(AAL2Unlock, "AA2VULK")
      #pragma map(AAL2UnlockHSM, "AA2VULKH")
      #pragma map(AAL2GetTokenInfoEx, "AA2VGTIE")
      #pragma map(AAL2GetTokenSingleInfo, "AA2VGTSI")
      #pragma map(AAL2GetTokenInfoExHSM, "AA2GTIEH")
      #pragma map(AAL2GetTokenSingleInfoHSM, "AA2GTSIH")
      #pragma map(AAL2ResetStaticPassword, "AA2VRSP")
      #pragma map(AAL2ResetStaticPasswordHSM, "AA2VRSPH")
      #pragma map(AAL2ChangeStaticPassword, "AA2VCSP")
      #pragma map(AAL2ChangeStaticPasswordHSM, "AA2VCSPH")
      #pragma map(AAL2ChangeEncryptedStaticPassword, "AA2CESP") /* 3.7.9.3 Encrypted Static Password Support (SLA) */
      #pragma map(AAL2ChangeEncryptedStaticPasswordHSM, "AA2CESPH") /* 3.7.9.3 Encrypted Static Password Support (SLA) */
      #pragma map(AAL2ChangeEncryptedStaticPasswordEs, "AA2CESPS") /* 3.7.11.1 Validation with Enhanced Security Support (SLA) */
      #pragma map(AAL2ChangeEncryptedStaticPasswordEsHSM, "AA2CESHS") /* 3.7.11.1 Validation with Enhanced Security Support (SLA) */
      #pragma map(AAL2GenUnlockAuthCode, "AA2GUAC")
      #pragma map(AAL2GenUnlockAuthCodeHSM, "AA2GUACH")
      #pragma map(AAL2AuthorizeUnlock, "AA2AUCK")
      #pragma map(AAL2AuthorizeUnlockHSM, "AA2AUCKH")
      #pragma map(AAL2MigrateBlob, "AA2MGBL")
      #pragma map(AAL2MigrateBlobHSM, "AA2MGBH")
      #pragma map(AAL2MigrateBlobHSMEx, "AA2MGBHX")
      #pragma map(AAL2GenKeySetHSM, "AA2GKSH")
      #pragma map(AAL2GenActivationCode, "AA2GACTC")
      #pragma map(AAL2GetSessionKey, "AA2GSSK")
      #pragma map(AAL2VerifyWIN, "AA2VFWIN")
      #pragma map(AAL2GenHASH, "AA2GNHSH")
      #pragma map(AAL2SyncTokenBlob, "AA2SYNTB")
      #pragma map(AAL2SyncTokenBlobEx, "AA2SYNBE")
      #pragma map(AAL2FinalizeHSM, "AA2FHSM")
      #pragma map(AAL2InitializeHSM, "AA2IHSM")
      #pragma map(AAL2OpenSessionHSM, "AA2OSHSM")
      #pragma map(AAL2CloseSessionHSM, "AA2CSHSM")
      #pragma map(AAL2GetTokenProperty, "AA2GTP")
      #pragma map(AAL2SetTokenProperty, "AA2STP")
      #pragma map(AAL2SyncTokenAndHost, "AA2STAH")
      #pragma map(AAL2SyncTokenAndHostHSM, "AA2STAHH")
      #pragma map(AAL2GenTLV, "AA2GTLV")
      #pragma map(AAL2GenTLVEx, "AA2GTLVX")
      #pragma map(AAL2GenDPBlobHSM, "AA2GDPBH")
      #pragma map(AAL2MXGenerateChallenge, "AA2MXGC")
      #pragma map(AAL2MXVerifyPassword, "AA2MXVP")
      #pragma map(AAL2MXGenAuthChar, "AA2MXGAC")
      #pragma map(AAL2GetDerivedKeyHSM, "AA2VGDKH")
      #pragma map(AAL2GenPassword, "AA2GNPW")
      #pragma map(AAL2GenPasswordEx, "AA2GNPWE")
      #pragma map(AAL2GenSignature, "AA2GNSG")
      #pragma map(AAL2GenSignatureEx, "AA2GNSGE")
      #pragma map(AAL2CINIT_APrepare, "AA2CIPC")
      #pragma map(AAL2CINIT_AProcess, "AA2CIXC")
      #pragma map(AAL2DPXInitEx, "AA2VINCE")
      #pragma map(AAL2DPXInit, "AA2VINC")
      #pragma map(AAL2DPXInitHSM, "AA2VINCH")
      #pragma map(AAL2DPXGetStaticVector, "AA2VGST")
      #pragma map(AAL2DPXGetToken, "AA2VGTC")
      #pragma map(AAL2DPXGetTokenHSM, "AA2VGTCH")
      #pragma map(AAL2DPXGetAllToken, "AA2GATC")
      #pragma map(AAL2DPXGetAllTokenHSM, "AA2GATCH")
      #pragma map(AAL2DPXGetTokenBlobs, "AA2VGTB")
      #pragma map(AAL2DPXGetTokenBlobsHSM, "AA2VGTBH")
      #pragma map(AAL2DPXClose, "AA2VCLC")
      #pragma map(AAL2DPXGetErrorMsg, "AA2VDEM")
      #pragma map(AAL2GetErrorMsg, "AA2VGEM")
      #pragma map(AAL2ConvTokenData, "AA2VCTD")
      #pragma map(AAL2QAGenQABlob, "AA2QGQB")
      #pragma map(AAL2QAGenQAHashData, "AA2QGQHD")
      #pragma map(AAL2QADecryptQABlob, "AA2QDQB")
      #pragma map(AAL2GenActivationCodeEx, "AA2QGACE")
      #pragma map(AAL2GenActivationCodeXErc, "AA2GACXE")
      #pragma map(AAL2GenActivationCodeXErcHSM, "AA2GACXH")
      #pragma map(AAL2GenQAKey, "AA2QGQK")
      /*********************************************************************/
      /* SystemPrograming C                                               */
      /*********************************************************************/
      #ifdef USE_SPC
        #include <spc.h>
          #pragma runopts(TRAP(OFF))
        #pragma environment(AAL2ResetTokenInfo)
        #pragma environment(AAL2GetTokenInfo)
        #pragma environment(AAL2DP500Test)
        #pragma environment(AAL2VerifyAll)
        #pragma environment(AAL2VerifyAllEs)
        #pragma environment(AAL2VerifyAllEsEx)
        #pragma environment(AAL2VerifyAllHSM)
        #pragma environment(AAL2VerifyAllEsHSM)
        #pragma environment(AAL2VerifyPassword)
        #pragma environment(AAL2VerifyPasswordEs)
        #pragma environment(AAL2VerifyPasswordEx)
        #pragma environment(AAL2VerifyPasswordHSM)
        #pragma environment(AAL2VerifyPasswordEsHSM)
        #pragma environment(AAL2VerifyPasswordHash)
        #pragma environment(AAL2VerifySignature)
        #pragma environment(AAL2VerifySignatureEs)
        #pragma environment(AAL2VerifySignatureEx)
        #pragma environment(AAL2VerifySignatureEsEx)
        #pragma environment(AAL2VerifySignatureHSM)
        #pragma environment(AAL2VerifySignatureEsHSM)
        #pragma environment(AAL2GenerateChallenge)
        #pragma environment(AAL2GenerateChallengeEx)
        #pragma environment(AAL2Unlock)
        #pragma environment(AAL2UnlockHSM)
        #pragma environment(AAL2GetTokenInfoEx)
        #pragma environment(AAL2GetTokenSingleInfo)
        #pragma environment(AAL2GetTokenInfoExHSM)
        #pragma environment(AAL2GetTokenSingleInfoHSM)
        #pragma environment(AAL2ResetStaticPassword)
        #pragma environment(AAL2ResetStaticPasswordHSM)
        #pragma environment(AAL2ChangeStaticPassword)
        #pragma environment(AAL2ChangeStaticPasswordHSM)
        #pragma environment(AAL2GenUnlockAuthCode)
        #pragma environment(AAL2GenUnlockAuthCodeHSM)
        #pragma environment(AAL2AuthorizeUnlock)
        #pragma environment(AAL2AuthorizeUnlockHSM)
        #pragma environment(AAL2MigrateBlob)
        #pragma environment(AAL2MigrateBlobHSM)
        #pragma environment(AAL2MigrateBlobHSMEx)
        #pragma environment(AAL2GenKeySetHSM)
        #pragma environment(AAL2GenActivationCode)
        #pragma environment(AAL2GetSessionKey)
        #pragma environment(AAL2VerifyWIN)
        #pragma environment(AAL2GenHASH)
        #pragma environment(AAL2SyncTokenBlob)
        #pragma environment(AAL2SyncTokenBlobEx)
        #pragma environment(AAL2FinalizeHSM)
        #pragma environment(AAL2InitializeHSM)
        #pragma environment(AAL2OpenSessionHSM)
        #pragma environment(AAL2CloseSessionHSM)
        #pragma environment(AAL2GetTokenProperty)
        #pragma environment(AAL2SetTokenProperty)
        #pragma environment(AAL2SyncTokenAndHost)
        #pragma environment(AAL2SyncTokenAndHostHSM)
        #pragma environment(AAL2GenTLV)
        #pragma environment(AAL2GenTLVEx)
        #pragma environment(AAL2GenDPBlobHSM)
        #pragma environment(AAL2MXGenerateChallenge)
        #pragma environment(AAL2MXVerifyPassword)
        #pragma environment(AAL2MXGenAuthChar)
        #pragma environment(AAL2GetDerivedKeyHSM)
        #pragma environment(AAL2DPXInitEx)
        #pragma environment(AAL2DPXInit)
        #pragma environment(AAL2DPXInitHSM)
        #pragma environment(AAL2DPXGetStaticVector)
        #pragma environment(AAL2DPXGetToken)
        #pragma environment(AAL2DPXGetTokenHSM)
        #pragma environment(AAL2DPXGetAllToken)
        #pragma environment(AAL2DPXGetAllTokenHSM)
        #pragma environment(AAL2DPXGetTokenBlobs)
        #pragma environment(AAL2DPXGetTokenBlobsHSM)
        #pragma environment(AAL2DPXClose)
        #pragma environment(AAL2DPXGetErrorMsg)
        #pragma environment(AAL2GetErrorMsg)
        #pragma environment(AAL2ConvTokenData)
        #pragma environment(AAL2QAGenQABlob)
        #pragma environment(AAL2QAGenQAHashData)
        #pragma environment(AAL2QADecryptQABlob)
        #pragma environment(AAL2GenActivationCodeEx)
        #pragma environment(AAL2GenActivationCodeXErc)
        #pragma environment(AAL2GenActivationCodeXErcHSM)
        #pragma environment(AAL2GenQAKey)
      #endif /*USE_SPC*/
    #else
      #pragma export(AAL2ResetTokenInfo)
      #pragma export(AAL2GetTokenInfo)
      #pragma export(AAL2DP500Test)
      #pragma export(AAL2VerifyAll)
      #pragma export(AAL2VerifyAllEs)
      #pragma export(AAL2VerifyAllEsEx)
      #pragma export(AAL2VerifyAllHSM)
      #pragma export(AAL2VerifyAllEsHSM)
      #pragma export(AAL2VerifyPassword)
      #pragma export(AAL2VerifyPasswordEs)
      #pragma export(AAL2VerifyPasswordEx)
      #pragma export(AAL2VerifyPasswordHSM)
      #pragma export(AAL2VerifyPasswordEsHSM)
      #pragma export(AAL2VerifySignature)
      #pragma export(AAL2VerifySignatureEs)
      #pragma export(AAL2VerifySignatureEx)
      #pragma export(AAL2VerifySignatureEsEx)
      #pragma export(AAL2VerifySignatureHSM)
      #pragma export(AAL2VerifySignatureEsHSM)
      #pragma export(AAL2GenerateChallenge)
      #pragma export(AAL2GenerateChallengeEx)
      #pragma export(AAL2Unlock)
      #pragma export(AAL2UnlockHSM)
      #pragma export(AAL2GetTokenInfoEx)
      #pragma export(AAL2GetTokenSingleInfo)
      #pragma export(AAL2GetTokenInfoExHSM)
      #pragma export(AAL2GetTokenSingleInfoHSM)
      #pragma export(AAL2ResetStaticPassword)
      #pragma export(AAL2ResetStaticPasswordHSM)
      #pragma export(AAL2ChangeStaticPassword)
      #pragma export(AAL2ChangeStaticPasswordHSM)
      #pragma export(AAL2ChangeEncryptedStaticPassword)
      #pragma export(AAL2ChangeEncryptedStaticPasswordHSM)
      #pragma export(AAL2ChangeEncryptedStaticPasswordEs)
      #pragma export(AAL2ChangeEncryptedStaticPasswordEsHSM)
      #pragma export(AAL2GenUnlockAuthCode)
      #pragma export(AAL2GenUnlockAuthCodeHSM)
      #pragma export(AAL2AuthorizeUnlock)
      #pragma export(AAL2AuthorizeUnlockHSM)
      #pragma export(AAL2MigrateBlob)
      #pragma export(AAL2MigrateBlobHSM)
      #pragma export(AAL2GenKeySetHSM)
      #pragma export(AAL2GenActivationCode)
      #pragma export(AAL2GetSessionKey)
      #pragma export(AAL2VerifyWIN)
      #pragma export(AAL2GenHASH)
      #pragma export(AAL2SyncTokenBlob)
      #pragma export(AAL2SyncTokenBlobEx)
      #pragma export(AAL2FinalizeHSM)
      #pragma export(AAL2InitializeHSM)
      #pragma export(AAL2OpenSessionHSM)
      #pragma export(AAL2CloseSessionHSM)
      #pragma export(AAL2GetTokenProperty)
      #pragma export(AAL2SetTokenProperty)
      #pragma export(AAL2SyncTokenAndHost)
      #pragma export(AAL2SyncTokenAndHostHSM)
      #pragma export(AAL2GenTLV)
      #pragma export(AAL2GenTLVEx)
      #pragma export(AAL2GenDPBlobHSM)
      #pragma export(AAL2MXGenerateChallenge)
      #pragma export(AAL2MXVerifyPassword)
      #pragma export(AAL2MXGenAuthChar)
      #pragma export(AAL2GetDerivedKeyHSM)
    	#pragma export(AAL2CINIT_APrepare)
    	#pragma export(AAL2CINIT_AProcess)
      #pragma export(AAL2DPXInitEx)
      #pragma export(AAL2DPXInit)
      #pragma export(AAL2DPXInitHSM)
      #pragma export(AAL2DPXGetStaticVector)
      #pragma export(AAL2DPXGetToken)
      #pragma export(AAL2DPXGetTokenHSM)
      #pragma export(AAL2DPXGetAllToken)
      #pragma export(AAL2DPXGetAllTokenHSM)
      #pragma export(AAL2DPXGetTokenBlobs)
      #pragma export(AAL2DPXGetTokenBlobsHSM)
      #pragma export(AAL2DPXClose)
      #pragma export (AAL2DPXGetErrorMsg)
      #pragma export (AAL2GetErrorMsg)
      #pragma export (AAL2ConvTokenData)
      #pragma export (AAL2QAGenQABlob)
      #pragma export (AAL2QAGenQAHashData)
      #pragma export (AAL2QADecryptQABlob)
      #pragma export (AAL2GenActivationCodeEx)
      #pragma export (AAL2GenActivationCodeXErc)
      #pragma export (AAL2GenActivationCodeXErcHSM)
      #pragma export (AAL2GenQAKey)
    #endif /*_OEMVS*/

  #endif /*__MVS__*/
  #ifndef C_TYPES_REDECLARATION
    #define C_TYPES_REDECLARATION    1
typedef char                  aat_ascii;
typedef unsigned char         aat_byte;
typedef short int             aat_int16;
typedef unsigned short int    aat_uint16;

#if defined(_64BIT) || defined (SOLARIS64BIT)
typedef int                   aat_int32;
typedef unsigned int          aat_word32;
#else
typedef long                  aat_int32;
typedef unsigned long         aat_word32;
#endif

  #endif /* C_TYPES_REDECLARATION */

  #ifdef WIN32
    #include <windows.h>
    #ifndef VDS_EXPORT
      #define VDS_EXPORT(type) type __stdcall
    #endif
  #else
    #ifndef VDS_EXPORT
      #define VDS_EXPORT(type) type
    #endif
  #endif /* #ifdef WIN32 */

  #define DES          0
  #define AES          1
  #define MD4          2
  #define MD5          3
  #define SHA_1        4
  #define HMAC         5
  #define PRF          6
  #define XOR          7
  #define WINHASH      8

  #define LANMAN      1
  #define NTLM        2
  #define NTLM2       4
  #define NTLM2USER   8
  #define NTLM2DOMAIN 16
  #define KRB5        32
  #define DPRSP       64
  #define CHAP        128
  #define MSCHAP      2
  #define MSCHAP2     256

  #define TW_DYNAMIC_WINDOWS          0x70000000L
  #define SW_UNIT_MINUTE              0x70000000L
  #define SW_DISCRETE                 0x01000000L


/*Property Value for AAL2GetTokenInfoEx and AAL2GetTokenProperty*/
  #define TOKEN_MODEL                 0x00000001L
  #define USE_COUNT                   0x00000002L
  #define LAST_TIME_USED              0x00000003L
  #define LAST_TIME_SHIFT             0x00000004L
  #define TIME_BASED_ALGO             0x00000005L
  #define STATIC_PWD_SUPPORTED        0x00000006L
  #define PIN_SUPPORTED               0x00000006L
  #define UNLOCK_SUPPORTED            0x00000007L
  #define PIN_CH_ON                   0x00000008L
  #define PIN_CH_FORCED               0x00000009L
  #define PIN_LEN                     0x0000000AL
  #define PIN_MIN_LEN                 0x0000000BL
  #define VIRTUAL_TOKEN_GRACE_PERIOD  0x0000000CL
  #define VIRTUAL_TOKEN_REMAIN_USE    0x0000000DL
  #define TOKEN_STATUS                0x0000000EL
  #define VIRTUAL_TOKEN_TYPE          0x0000000FL
  #define LAST_RESPONSE_TYPE          0x00000010L
  #define ERROR_COUNT                 0x00000011L
  #define EVENT_VALUE                 0x00000012L
  #define SYNC_WINDOWS                0x00000013L
  #define LAST_EVENT_VALUE            0x00000014L
  #define PIN_ENABLED                 0x00000015L
  #define EVENT_BASED_ALGO            0x00000016L
  #define AMOUNT_SUPPORT              0x00000017L /* EMV CAP Token Only */
  #define IMK_LABEL                   0x00000018L /* EMV CAP Token Only */
  #define KCV_TYPE                    0x00000019L /* EMV CAP Token Only */
  #define KCV_VALUE                   0x0000001AL /* EMV CAP Token Only */
  #define STRONG_HOST_CODE_APP        0x0000001BL
  #define CODE_WORD                   0x0000001CL
  #define AUTH_MODE                   0x0000001DL


/*Property Value for the Static PIN*/
  #define STATIC_PIN_NOT_SUPPORTED  0x00000000L
  #define STATIC_PIN_SUPPORTED      0x00000001L
  #define STATIC_PIN_ENABLED        0x00000001L
  #define STATIC_PIN_DISABLED       0x00000002L
  #define FORCE_PIN_CHANGE          0x00000001L

/*Property Value for the Status*/
  #define VIRTUAL_TOKEN_SUPPORTED    0x20
  #define PRIMARY_TOKEN_ENABLED      0x80
  #define VIRTUAL_TOKEN_ENABLED      0x40
  #define VIRTUAL_REMAIN_USE         0x04

  #define INT_VALUE                  0x00010000L


/* Allowed Item Tags for TTLVItem in AAL2GenTLV() */
#define IT_AID                      0x9F06    /* Application Identifier - AID */
#define IT_AIP                      0x82      /* Application Interchange Profile - AIP */
#define IT_ATC                      0x9F36    /* Application Transaction Counter - ATC */
#define IT_IAD                      0x9F10    /* Issuer Application Data - IAD */
#define IT_CID                      0x9F27    /* Cryptogram Information Data - CID */
#define IT_IAF                      0x9F55    /* Issuer Authentication Flag */
#define IT_IIPB                     0x9F56    /* Issuer Internet Proprietary Bitmap */
#define IT_CDOL1                    0x8C      /* Terminal Data */
#define IT_CARD_DATA                0x02      /* Card Data (Proprietary Tag) */
/*#define IT_RSPTYP                 0x03         Obsolete since CAP E specifications*/


/* Allowed Item Tag Formats for TTLVItem in AAL2GenTLV() */
#define ITF_CHAR  0x00
#define ITF_BYTE  0x01

/* EMV Schemes - for Key derivation and Cryptogram Generation */
#define ESA_ETC_2_1_3     0x10000213     /* Europay Test Cards (Pay Now & Pay Later Security Aspects v2.1/2.3 */
#define ESA_2_3           0x10000230     /* Europay Security Aspects v2.3 */
#define ESA_3_0           0x10000300     /* Europay Security Aspects v3.0 */
#define ESA_EMV2000_8_4   0x10300042     /* Europay Security Aspects v4.0 (EMV2000 - M/Chip 4) H=8, b=4 */
#define ESA_EMV2000_16_2  0x10300081     /* Europay Security Aspects v4.0 (EMV2000 - M/Chip 4) H=16, b=2 */
#define ESA_EMV2000_4_10  0x10300025     /* Europay Security Aspects v4.0 (EMV2000 - M/Chip 4) H=4, b=10 */
#define ESA_BKS_35        0x10341028     /* BANKSYS V3.5 (EMV2000) H=4, b=16 */
#define ESA_BKS_55        0x10141000     /* BANKSYS V5.5  */
#define ESA_BKS_56        0x10140000     /* BANKSYS V5.6  */
#define ESA_MCHIP_2_1     0x10500000     /* Europay Security Aspects v4.0 (M/Chip 2.1) */
#define ESA_ZENGINKYO     0x11100000	   /* Zenginkyo Card */
#define ESA_HANDELSBANK   0x10880000     /* Handelsbank card (UKIS v3.0 variant) */
#define ESA_UKIS_3_0      0x10810000     /* UKIS v3.0 (VISA VIS v1.2) + Visa Date */
#define ESA_MCPA          0x10001390     /* MCPA */
#define ESA_CLIP_0_5      0x10002050     /* CLIP Security Aspects v0.5 */
#define ESA_SECCOS_1_0    0x10003100     /* SECCOS v1.0 */
#define ESA_APSS_3_1_A    0x10004300     /* APSS v3.1a */


/*Data Fields TAG For Digipass Blob Generation*/

#define TAG_SERNUMB10		0x01
#define TAG_UNL64KEY 		0x02
#define TAG_UNLCHLLNG		0x03
#define TAG_UNLCHLCHK		0x04
#define TAG_UNLRSPLNG		0x05
#define TAG_UNLRSPCHK		0x06
#define TAG_TKMODEL     0x07
#define TAG_TDESFLAG    0x08


#define TAG_PINFATAL 		0x0C
#define TAG_PINWAITNUMB	0x0D
#define TAG_PINWAITTIME	0x0E
#define TAG_PINERASE		0x0F
#define TAG_IPIN		  0x10
#define TAG_PINLNG		0x11
#define TAG_PINCHGON 	0x12
#define TAG_PINSAVE		0x13
#define TAG_APPLNAME	0x14
#define TAG_DES64KEY 	0x15
#define TAG_TDES64KEY	0x16
#define TAG_OFFSET		0x17
#define TAG_IVRIGHT		0x18
#define TAG_IVLEFT		0x19
#define TAG_DTFNUMB		0x1A
#define TAG_DTF1LNGMN	0x1B
#define TAG_DTF2LNGMN	0x1C
#define TAG_DTF3LNGMN	0x1D
#define TAG_DTF4LNGMN	0x1E
#define TAG_DTF5LNGMN	0x1F
#define TAG_DTF6LNGMN	0x20
#define TAG_DTF7LNGMN	0x21
#define TAG_DTF8LNGMN	0x22
#define TAG_DTF1LNGTY	0x23
#define TAG_DTF2LNGTY	0x24
#define TAG_DTF3LNGTY	0x25
#define TAG_DTF4LNGTY	0x26
#define TAG_DTF5LNGTY	0x27
#define TAG_DTF6LNGTY	0x28
#define TAG_DTF7LNGTY	0x29
#define TAG_DTF8LNGTY	0x2A
#define TAG_DTF1LNGMX	0x2B
#define TAG_DTF2LNGMX	0x2C
#define TAG_DTF3LNGMX	0x2D
#define TAG_DTF4LNGMX	0x2E
#define TAG_DTF5LNGMX	0x2F
#define TAG_DTF6LNGMX	0x30
#define TAG_DTF7LNGMX	0x31
#define TAG_DTF8LNGMX	0x32
#define TAG_DTF1CHK		0x33
#define TAG_DTF2CHK		0x34
#define TAG_DTF3CHK		0x35
#define TAG_DTF4CHK		0x36
#define TAG_DTF5CHK		0x37
#define TAG_DTF6CHK		0x38
#define TAG_DTF7CHK		0x39
#define TAG_DTF8CHK		0x3A
#define TAG_HOSTVER		0x3B
#define TAG_RSPLNG		0x3C
#define TAG_RSPTY		  0x3D
#define TAG_RSPCHK		0x3E
#define TAG_XTNDRSP		0x3F
#define TAG_RSPXTNSN	0x40
#define TAG_CODEWORD	0x41
#define TAG_DAYCUT		0x42
#define TAG_TOMORROW	0x43
#define TAG_TODAY		  0x44
#define TAG_ROOT		  0x45
#define TAG_ACTVCODE	0x46
#define TAG_PINFORCED 0x47
#define TAG_PINCHGLNG 0x48





#define MAX_EMV_CAP_DATAFIELDS        10
#define DATAFIELD_LENGTH              20

/* TDigipassBlob Data Fields Definition - Character model */
typedef struct
  {                                /* Field Description            : Position  :   Length  */
  aat_ascii    Serial[10];         /* Serial #                     : x00 - 000 : x0A - 010 */
  aat_ascii    AppName[12];        /* Application Name             : x0A - 010 : x0C - 012 */
  aat_byte     DPFlags[2];         /* Reserved Flag bytes          : x16 - 022 : x02 - 002 */
  aat_ascii    Blob[224];          /* Base64 encoded data          : x18 - 024 : xE0 - 224 */
  } TDigipassBlob;                 /* Total Structure Length       : xF8 - 248 : xF8 - 248 */
  #define TDigipassBlobSize   248

/* TDigipassInfo Data Fields Definition - Display Model */
typedef struct
  {                      /* Field Description         : Position  :   Length  */
  aat_ascii    TokenModel[5+1];       /* Physical Token Type       : x00 - 000 : x06 - 006 */
  aat_ascii    UseCount[6+1];         /* Usage Count               : x06 - 006 : x07 - 007 */
  aat_ascii    LastTimeUsed[24+1];    /* Last Token Time Used      : x0D - 013 : x19 - 025 */
  aat_ascii    LastTimeShift[6+1];    /* Last Token Time Shift     : x26 - 038 : x07 - 007 */
  aat_ascii    ErrorCount[3+1];       /* Current Error Count       : x2D - 045 : x04 - 004 */
  aat_ascii    CodeWord[8+1];         /* Binary Codeword           : x31 - 049 : x09 - 009 */
  aat_ascii    TripleDes[3+1];        /* Triple DES flag           : x3A - 058 : x04 - 004 */
  aat_ascii    MaxInputFields[1+1];   /* Challenge/Data Fields nbr : x3E - 062 : x02 - 002 */
  aat_ascii    ResponseLength[2+1];   /* Response Length           : x40 - 064 : x03 - 003 */
  aat_ascii    ResponseType[3+1];     /* Output Type               : x43 - 067 : x04 - 004 */
  aat_ascii    ResponseChecksum[3+1]; /* Checksum Requested Flag   : x47 - 071 : x04 - 004 */
  aat_ascii    TimeStepUsed[6+1];     /* Time step used if any     : x4B - 075 : x06 - 006 */
  } TDigipassInfo;                    /* Total Structure Length    : x51 - 081 : x51 - 081 */

/* TKernelParms Definition */
typedef struct
  {
  aat_int32    ParmCount;          /* Number of valid parameters in this list              */
  aat_int32    ITimeWindow;        /* Identification Window size in nbr of time steps      */
  aat_int32    STimeWindow;        /* Signature Window size in nbr of time steps           */
  aat_int32    DiagLevel;          /* Requested Diagnostic Level                           */
  aat_int32    GMTAdjust;          /* GMT Time adjustment to perform                       */
  aat_int32    CheckChallenge;     /* Verify Challenge Corrupted (mandatory for Gordian)   */
  aat_int32    IThreshold;         /* Identification Error Threshold                       */
  aat_int32    SThreshold;         /* Signature Error Threshold                            */
  aat_int32    ChkInactDays;       /* Check Inactive Days                                  */
  aat_int32    DeriveVector;       /* Vector used to make Data Encryption unique           */
  aat_int32    SyncWindow;         /* Synchronisation Time Window (h)                      */
  aat_int32    OnLineSG;           /* On line  Signature                                   */
  aat_int32    EventWindow;        /* Event Window size in nbr of iterations               */
  aat_int32    HSMSlotId;          /* HSM Slot id uses to store DB and Transport Key       */
  aat_int32    StorageKeyId;       /* Key Id uses to read (Decrypt) DIGIPASS Blob          */
  aat_int32    TransportKeyId;     /* Key Id uses to write (Encrypt) DIGIPASS Blob to DB   */
  aat_int32    StorageDeriveKey1;  /* Storage Derivation Key Part 1                        */
  aat_int32    StorageDeriveKey2;  /* Storage Derivation Key Part 2                        */
  aat_int32    StorageDeriveKey3;  /* Storage Derivation Key Part 3                        */
  aat_int32    StorageDeriveKey4;  /* Storage Derivation Key Part 4                        */
  } TKernelParms;

/* TCinitHandle Definition */
typedef struct
  {
  aat_ascii    init_res[17];       /* intermediate result from init_key                    */
  aat_ascii    DataModel;          /* Indicate requested Data Model: 0=Binary, 1=Base64    */
  } TCinitHandle;

/* TDPXHandle Definition */
typedef struct
  {
  void *pHandleDpxContext; /* Pointer to DPX Context structure                     */
  void *pHandleDpxInitKey; /* Pointer to DPX InitKey structure                     */
  } TDPXHandle;

typedef struct
  {
  aat_word32 bv_len;
  aat_ascii  *bv_val;
  } Tval;

typedef struct
  {
  aat_word32       Type;
  aat_uint16       Size;
  aat_uint16       AllocatedSize;
  aat_byte         *Value;
  } TData;    /* Total size: 12 byte */

typedef struct
  {
  aat_word32        Size;
  aat_word32        Challenges;
  TData             *Challenge;
  aat_word32        Responses;
  TData             *Response;
  aat_word32        Hashes;
  TData             *Hash;
  } TAuthParms;    /* Total size: 28 byte */

typedef struct
  {
  aat_word32        Size;
  aat_word32        Infos;
  TData             *Info;
  } TDigipassInfoEx;    /* Total size: 20 byte */

typedef struct
  {
  aat_byte              Key[16];
  }  TKeyByte; /* Total size: 16 bytes */

typedef struct
  {
  aat_byte              KeyIndex;
  aat_ascii             KeyLabel[15];
  aat_byte              KCV[3];
  aat_byte              KCVType;
  }  THSMKeyRef; /* Total size: 20 bytes */

typedef struct
  {
  aat_byte    fKeyType;
  TKeyByte	  KeyByte;
  THSMKeyRef 	HSMKeyRef;
  aat_byte    Reserved[3];
  } TKey; /* Total size: 40 bytes */


typedef struct
{
  aat_uint16  Tag;
  aat_word32  Size;
  aat_uint16  Format;
  aat_uint16  Mandatory;
  aat_uint16  Found;
  aat_word32  iMinLen;
  aat_word32  iMaxLen;
  aat_byte    *Value;
} TTLVItem;


typedef struct
{
  aat_byte   Tag;
  aat_byte   Size;
  aat_byte   Format;
  aat_byte   Value[29];
} DPTLVItem;

  #ifdef __cplusplus
extern "C" {
#endif


/*#ifdef _EMV*/

/*********************************************************************/
/* Response Validation Using Kernel Functions in EMV Mode1           */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2VerifyEMVCAPMode1(void          *pHSMContext,
                                              TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *CAPToken,
                                              aat_ascii     *Challenge,
                                              aat_ascii     *TransactionAmount,
                                              aat_ascii     *TransactionCurrency,
                                              aat_ascii     *aReturnHostCodeOut,
                                              aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* Generate CAP Token Using Kernel Functions in EMV Mode1            */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenEMVCAPMode1(void          *pHSMContext,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *CAPToken,
                                            aat_ascii     *Challenge,
                                            aat_ascii     *TransactionAmount,
                                            aat_ascii     *TransactionCurrency,
                                            aat_ascii     *aReturnHostCodeOut,
                                            aat_int32     *ReturnHostCodeLenOut);

/********************************************************************/
/* Response Validation Using Kernel Functions in EMV Mode2          */
/********************************************************************/
  VDS_EXPORT(aat_int32) AAL2VerifyEMVCAPMode2(void          *pHSMContext,
                                              TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *CAPToken,
                                              aat_ascii      TDS[MAX_EMV_CAP_DATAFIELDS][20],
                                              aat_int32      TDSFlag,
                                              aat_ascii     *aReturnHostCodeOut,
                                              aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* Generate CAP Token Using Kernel Functions in EMV Mode2           */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenEMVCAPMode2(void          *pHSMContext,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *CAPToken,
                                            aat_ascii      TDS[MAX_EMV_CAP_DATAFIELDS][DATAFIELD_LENGTH],
                                            aat_int32      TDSFlag,
                                            aat_ascii     *aReturnHostCodeOut,
                                            aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* Response Validation Using Kernel Functions in EMV Mode3           */
/*********************************************************************/
  VDS_EXPORT(aat_int32)AAL2VerifyEMVCAPMode3( void          *pHSMContext,
                                              TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *CAPToken,
                                              aat_ascii     *Challenge,
                                              aat_ascii     *aReturnHostCodeOut,
                                              aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* Generate CAP Token Using Kernel Functions in EMV Mode3            */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenEMVCAPMode3(void          *pHSMContext,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *CAPToken,
                                            aat_ascii     *Challenge,
                                            aat_ascii     *aReturnHostCodeOut,
                                            aat_int32     *ReturnHostCodeLenOut);


/*********************************************************************/
/* Generate EMV Blob Ex                                              */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenEMVBlobEx ( void          *pReserved,
                                           TDigipassBlob *DPData,
                                           TKernelParms  *CallParms,
                                           aat_byte      *bTLVData,
                                           aat_int32      nTLVDataLength,
                                           aat_word32     EMVType,
                                           TKey          *Key,
                                           aat_ascii     *SerialNum);


/*********************************************************************/
/* Generate EMV TLV                                                  */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenTLV( TTLVItem       Values[],
                                    aat_word32     ValueCount,
                                    aat_byte      *bTLVData,
                                    aat_word32    *nTLVDataLength,
                                    aat_word32     nTLVDataAllocatedSize);
/*#endif*/ /*_EMV*/

/*********************************************************************/
/* Generate challenges for Matrix Card                               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2MXGenerateChallenge (   TDigipassBlob   *MXCardBlob,
                                                    TKernelParms    *CallParms,
                                                    aat_int32        MXCardSequenceNumber,
                                                    aat_int32        RowsNumber,
                                                    aat_int32        ColumnsNumber,
                                                    aat_int32        SecurityLevel,
                                                    aat_ascii       *Challenge);

/*********************************************************************/
/* Generate Matrix Card user authentication characters               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2MXGenAuthChar ( TDigipassBlob *MXCardBlob,
                                            TKernelParms  *CallParms,
                                            aat_int32      MXCardSequenceNumber,
                                            aat_int32	   RowIndex,
                                            aat_int32      ColumnIndex,
                                            aat_ascii     *UserAuthChar,
                                            aat_ascii     *HostAuthChar);

/*********************************************************************/
/* Verify Maxtrix Card password                                      */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2MXVerifyPassword ( void          *pHSMContext,
                                               TDigipassBlob *MXCardBlob,
                                               TKernelParms  *CallParms,
                                               aat_int32      MXCardSequenceNumber,
                                               aat_ascii     *Challenge,
                                               aat_ascii     *Password,
                                               aat_ascii     *ReturnHostCode);



/*********************************************************************/
/* Response or Signature Validation with Time and Event              */
/*  Using  Kernel Functions                                          */
/*********************************************************************/
   VDS_EXPORT(aat_int32)  AAL2VerifyAll(TDigipassBlob  *DPData,
                                        TKernelParms    *CallParms,
                                        aat_ascii       *aResponseIn,
                                        aat_ascii       DataField[10] [20],
                                        aat_int32       FieldCount,
                                        aat_int32       TimeValueIn,
                                        aat_word32      EventValueIn,
                                        aat_ascii       *aReturnHostCodeOut,
                                        aat_int32       *ReturnHostCodeLenOut);

/*********************************************************************/
/* Response or Signature Validation with Time and Event              */
/* Using  Kernel Functions                                           */
/* HSM Support                                                       */
/*********************************************************************/
   VDS_EXPORT(aat_int32)  AAL2VerifyAllHSM(void           *pHSMContext,
                                           TDigipassBlob  *DPData,
                                           TKernelParms   *CallParms,
                                           aat_ascii      *aResponseIn,
                                           aat_ascii      DataField[10] [20],
                                           aat_int32      FieldCount,
                                           aat_int32      TimeValueIn,
                                           aat_word32     EventValueIn,
                                           aat_ascii      *aReturnHostCodeOut,
                                           aat_int32      *ReturnHostCodeLenOut);

/*********************************************************************/
/* Response or Signature Validation with Time and Event              */
/* Using  Kernel Functions                                           */
/* Enhanced Security                                                 */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifyAllEs (TDigipassBlob  *DPData,
                                       TKernelParms    *CallParms,
                                       aat_ascii       *aResponseIn,
                                       aat_ascii       *DataField[10],
                                       aat_int32       FieldCount,
                                       aat_int32       TimeValueIn,
                                       aat_word32      EventValueIn,
                                       aat_ascii       *aServerPublicKey,
                                       aat_ascii       *aReturnHostCodeOut,
                                       aat_int32       *ReturnHostCodeLenOut);

/*********************************************************************/
/* Response or Signature Validation with Time and Event              */
/* Using  Kernel Functions                                           */
/* HSM support + Enhanced Security                                   */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifyAllEsHSM ( void           *pHSMContext,
                                           TDigipassBlob  *DPData,
                                           TKernelParms   *CallParms,
                                           aat_ascii      *aResponseIn,
                                           aat_ascii      *DataField[10],
                                           aat_int32      FieldCount,
                                           aat_int32      TimeValueIn,
                                           aat_word32     EventValueIn,
                                           aat_ascii      *aServerPublicKey,
                                           aat_ascii      *aReturnHostCodeOut,
                                           aat_int32      *ReturnHostCodeLenOut);

/*********************************************************************/
/* Response Validation Using Kernel Functions                        */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifyPassword(TDigipassBlob *DPData,
                                            TKernelParms  *KParms,
                                            aat_ascii     *Password,
                                            aat_ascii     *Challenge);

/*********************************************************************/
/* Response Validation + HostCode generation Using Kernel Functions  */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifyPasswordEx(TDigipassBlob *DPData,
                                              TKernelParms  *KParms,
                                              aat_ascii     *Password,
                                              aat_ascii     *Challenge,
                                              aat_ascii     *ReturnHostCode,
                                              aat_int32     *ReturnHostCodeLength);

/*********************************************************************/
/* Response Validation + HostCode generation Using Kernel Functions  */
/* HSM support                                                       */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifyPasswordHSM( void          *pHSMContext,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *KParms,
                                                aat_ascii     *Password,
                                                aat_ascii     *Challenge,
                                                aat_ascii     *ReturnHostCode,
                                                aat_int32     *ReturnHostCodeLength);

/*********************************************************************/
/* Response Validation + HostCode generation Using Kernel Functions  */
/* Enhanced Security                                                 */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifyPasswordEs ( TDigipassBlob *DPData,
                                             TKernelParms  *CallParms,
                                             aat_ascii     *aResponseIn,
                                             aat_ascii     *aChallengeIn,
                                             aat_ascii     *aServerPublicKey,
                                             aat_ascii     *aReturnHostCodeOut,
                                             aat_int32     *ReturnHostCodeLenOut);


/*********************************************************************/
/* Response Validation + HostCode generation Using Kernel Functions  */
/* HSM support + Enhanced Security                                   */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifyPasswordEsHSM ( void          *pHSMContext,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aResponseIn,
                                                aat_ascii     *aChallengeIn,
                                                aat_ascii     *aServerPublicKey,
                                                aat_ascii     *aReturnHostCodeOut,
                                                aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* Signature Validation Using Kernel Functions                       */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifySignature( TDigipassBlob *DPData,
                                              TKernelParms  *KParms,
                                              aat_ascii     *Signature,
                                              aat_ascii     SignedDataFields[8][20],
                                              aat_int32     FieldCount,
                                              aat_int32     DeferredSignatureDate);

/*********************************************************************/
/* Signature Validation + Confirmation Code generation Using Kernel  */
/* Functions                                                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifySignatureEx(TDigipassBlob *DPData,
                                               TKernelParms  *KParms,
                                               aat_ascii     *Signature,
                                               aat_ascii     SignedDataFields[8][20],
                                               aat_int32     FieldCount,
                                               aat_int32     DeferredSignatureDate,
                                               aat_ascii    *ConfirmationCode,
                                               aat_int32    *ConfirmationCodeLength);

/*********************************************************************/
/* Signature Validation + Confirmation Code generation Using Kernel  */
/* Functions                                                         */
/* HSM support                                                       */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2VerifySignatureHSM(void          *pHSMContext,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *KParms,
                                                aat_ascii     *Signature,
                                                aat_ascii     SignedDataFields[8][20],
                                                aat_int32     FieldCount,
                                                aat_int32     DeferredSignatureDate,
                                                aat_ascii    *ConfirmationCode,
                                                aat_int32    *ConfirmationCodeLength);

/*********************************************************************/
/* Signature Validation + ConfCode generation Using Kernel Functions */
/* Enhanced Security                                                 */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifySignatureEs ( TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *Signature,
                                              aat_ascii     *SignedDataFields[8],
                                              aat_int32      FieldCount,
                                              aat_int32      DeferredSignatureData,
                                              aat_ascii     *aServerPublicKey,
                                              aat_ascii     *aConfirmationCodeOut,
                                              aat_int32     *ConfirmationCodeLenOut);

/*********************************************************************/
/* Signature Validation + ConfCode generation Using Kernel Functions */
/* HSM support + Enhanced Security                                   */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifySignatureEsHSM (void          *pHSMContext,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *Signature,
                                                aat_ascii     *SignedDataFields[8],
                                                aat_int32      FieldCount,
                                                aat_int32      DeferredSignatureData,
                                                aat_ascii     *aServerPublicKey,
                                                aat_ascii     *aConfirmationCodeOut,
                                                aat_int32     *ConfirmationCodeLenOut);


/*********************************************************************/
/* Generate Challenge Using Kernel Functions                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenerateChallenge(TDigipassBlob *DPData,
                                               TKernelParms  *KParms,
                                               aat_ascii     *Challenge,
                                               aat_int32     *ChallengeLength);

/*********************************************************************/
/* Generate Challenge Using Kernel Functions                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenerateChallengeHSM(  void          *pHSMContext,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *KParms,
                                                    aat_ascii     *Challenge,
                                                    aat_int32     *ChallengeLength);

  /*********************************************************************/
/* Generate Challenge Using Kernel Functions                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenerateChallengeEx(TDigipassBlob *DPData,
                                                 TKernelParms  *KParms,
                                                 aat_ascii     *Challenge,
                                                 aat_int32     *ChallengeLength,
                                                 aat_ascii     *ChallengeMsg);

/*********************************************************************/
/* Generate Unlock Message Using Kernel Functions                    */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2Unlock(  TDigipassBlob *DPData,
                                      TKernelParms  *KernelParms,
                                      aat_ascii     *RandomNumber,
                                      aat_ascii     *UnlockCode);

/*********************************************************************/
/* Generate Unlock Message Using Kernel Functions                    */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2UnlockHSM( void          *pHSMContext,
                                        TDigipassBlob *DPData,
                                        TKernelParms  *KernelParms,
                                        aat_ascii     *RandomNumber,
                                        aat_ascii     *UnlockCode);


/*********************************************************************/
/* Validate code generated by "T" button of a Digipass 500           */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2DP500Test(aat_ascii *TestCode,
                                       aat_ascii *HostDateTime,
                                       aat_int32 *ClockShift);

/*********************************************************************/
/* Reset all time and error fields for a token                       */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2ResetTokenInfo(TDigipassBlob *DPData,
                                            TKernelParms  *CallParms);

/*********************************************************************/
/* Get Information from a Digipass from TDigipassBlob                */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GetTokenInfo(TDigipassBlob *DPData,
                                          TKernelParms  *CallParms,
                                          TDigipassInfo *DPInfo);

/*********************************************************************/
/* Initialize DPX file Import Process                                */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2DPXInit(TDPXHandle *dpx_Handle,
                                     aat_ascii  *pFileName,
                                     aat_ascii  *InitKey,
                                     aat_int16  *appli_count,
                                     aat_ascii  *appl_names,
                                     aat_int16  *token_count);

  VDS_EXPORT(aat_int32) AAL2DPXInitHSM(TDPXHandle *dpx_Handle,
                                     aat_ascii *pFileName ,
                                     aat_ascii *InitKey,
                                     aat_int16 *appli_count,
                                     aat_ascii *appl_names,
                                     aat_int32 *token_count,
                                     aat_ascii *Hsm_Key_names,
                                     aat_ascii *Hsm_Key_KCV);


/*********************************************************************/
/* Initialize DPX file Import Process using extra derivation keys    */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2DPXInitEx(TDPXHandle  *dpx_Handle,
                                      aat_ascii *pFileName ,
                                      aat_ascii *InitKey,
                                      aat_ascii *OperKey,
                                      aat_ascii *AdminKey,
                                      aat_int16 *appli_count,
                                      aat_ascii *appl_names,
                                      aat_int16 *token_count);

/*********************************************************************/
/* Get static vector from DPX file for software tokens               */
/*********************************************************************/
 VDS_EXPORT(aat_int32) AAL2DPXGetStaticVector ( TDPXHandle    * dpx_Handle,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *StaticVector,
                                                aat_int32     *StaticVectorLen);

/*********************************************************************/
/* Obtain a Digipass Description & Data Block from DPX File          */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2DPXGetToken(TDPXHandle    *dpx_Handle,
                                         TKernelParms  *CallParms,
                                         aat_ascii     *Select_appl_name,
                                         aat_ascii     *sw_out_serial_No,
                                         aat_ascii     *sw_out_type,
                                         aat_ascii     *sw_out_authmode,
                                         TDigipassBlob *DPData);

/*********************************************************************/
/* Obtain multiple Description & Data Blocks for a Digipass from DPX */
/* File, 8 max                                                       */
/*********************************************************************/

  VDS_EXPORT(aat_int32)  AAL2DPXGetTokenBlobs(TDPXHandle    *dpx_Handle,
                                              TKernelParms  *CallParms,
                                              aat_int16     *appli_count,
                                              aat_ascii      sw_out_appli[8][23],
                                              aat_ascii     *sw_out_type,
                                              aat_ascii      sw_out_authmode[8][2],
                                              TDigipassBlob  DPData[8]);

/*********************************************************************/
/* Obtain multiple Description & Data Blocks for a Digipass from DPX */
/* File, 8 max                                                       */
/*********************************************************************/

  VDS_EXPORT(aat_int32)  AAL2DPXGetTokenBlobsHSM(void          *pHSMContext,
                                                 TDPXHandle    *dpx_Handle,
                                                 TKernelParms  *CallParms,
                                                 aat_int16     *appli_count,
                                                 aat_ascii      sw_out_appli[8][23],
                                                 aat_ascii     *sw_out_type,
                                                 aat_ascii      sw_out_authmode[8][2],
                                                 TDigipassBlob  DPData[8]);


/*********************************************************************/
/* Obtain a Digipass Description & Data Block from DPX File          */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2DPXGetTokenHSM(   void          *pHSMContext,
                                               TDPXHandle    *dpx_Handle,
                                               TKernelParms  *CallParms,
                                               aat_ascii     *Select_appl_name,
                                               aat_ascii     *sw_out_serial_No,
                                               aat_ascii     *sw_out_type,
                                               aat_ascii     *sw_out_authmode,
                                               TDigipassBlob *DPData);

/*********************************************************************/
/* Close DPX File Import Process                                     */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2DPXClose(TDPXHandle *dpx_Handle);

/*********************************************************************/
/* Prepare CINIT_A record transformation using Header and Init Key   */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2CINIT_APrepare(TCinitHandle *CHandle,
                                            aat_ascii    *CINIHeaderRecord,
                                            aat_ascii    *init_key);

/*********************************************************************/
/* Obtain a Digipass Description & Data Block from  Data record      */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2CINIT_AProcess(TCinitHandle  *CHandle,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *CINIDataRecord,
                                            aat_ascii     *Serial,
                                            aat_ascii     *DigipassType,
                                            aat_ascii     *AuthMode,
                                            TDigipassBlob *DPData);

/*********************************************************************/
/* Convert a numeric error code to readable text for DPX errors      */
/*********************************************************************/
  VDS_EXPORT(aat_ascii *)  AAL2DPXGetErrorMsg(aat_int32 errorNum,
                                              aat_ascii *szBuffer);

/*********************************************************************/
/* Convert a numeric error code to readable text                     */
/*********************************************************************/
  VDS_EXPORT(aat_ascii *)  AAL2GetErrorMsg(aat_int32 errorNum,
                                           aat_ascii *szBuffer);

/*********************************************************************/
/* Convert Legacy Data Format to Digipass Data Block                 */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2ConvTokenData(  TKernelParms  *CallParms,
                                             aat_ascii     *sw_serial_No,
                                             aat_ascii     *sw_type,
                                             aat_ascii     *sw_record,
                                             aat_ascii     *sw_out_serial_No,
                                             aat_ascii     *sw_out_type,
                                             aat_ascii     *sw_out_authmode,
                                             TDigipassBlob *sw_EncodedData);

/*********************************************************************/
/* Check Digipass password Encryted with MSCHAP                      */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2VerifyWIN(TDigipassBlob *DPData,
                                      TKernelParms  *CallParms,
                                      aat_ascii     *Challenge,
                                      TAuthParms    *InOutParms);
/*********************************************************************/
/* Check Digipass password Encryted with MSCHAP                      */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2VerifyPasswordHash(TDigipassBlob *DPData,
                                             TKernelParms  *CallParms,
                                             aat_ascii     *Challenge,
                                             TAuthParms    *WinParms,
                                             aat_ascii     *aExternalStaticPassword,
                                             aat_int32     ExternalStaticPasswordLen);

/*********************************************************************/
/* Generate a SESSION Key from a Digipass Response                   */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GetSessionKey(TDigipassBlob *DPData,
                                          TKernelParms  *CallParms,
                                          aat_ascii     *Challenge,
                                          aat_ascii     *SeedBuffer,
                                          aat_word32    SeedLength,
                                          aat_word32    CombinationAlgorithm,
                                          aat_word32    DerivationAlgorithm,
                                          aat_word32    DerivationAlgorithmParameters,
                                          aat_word32    NumberOfDerivationRounds,
                                          aat_word32    DecryptionAlgorithm,
                                          aat_word32    DecryptionAlgorithmParameters,
                                          aat_word32    NumberOfRedundancyBits,
                                          aat_ascii     *DataBuffer,
                                          aat_word32    *DataLength);

/*********************************************************************/
/* Generate HASH Code using MD4 MD5 or SHA_1                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenHASH(  aat_ascii     *InputBuffer,
                                      aat_word32    InputBufferLength,
                                      aat_word32    HASHAlgorithm,
                                      aat_ascii     *OutputBuffer,
                                      aat_word32    HASHLength,
                                      aat_word32    HASHFormat,
                                      aat_word32    CheckDigit);

/*********************************************************************/
/* Generate ActivationCode  for DPSoft                               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenActivationCode(TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *aMasterKey,
                                              aat_int32     *ActivationCodeFormat,
                                              aat_ascii     *aActivationCode);

/*********************************************************************/
/* Reset Static Password                                             */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ResetStaticPassword(  TDigipassBlob *DPData,
                                                  TKernelParms  *CallParms);

/*********************************************************************/
/* Reset Static Password HSM Version                                 */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ResetStaticPasswordHSM( void          *pHSMContext,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms);

/*********************************************************************/
/* Change Static Password                                            */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeStaticPassword (TDigipassBlob *DPData,
                                                  TKernelParms  *CallParms,
                                                  aat_ascii     *NewStaticPassword1,
                                                  aat_ascii     *NewStaticPassword2);


/*********************************************************************/
/* Change Static Password HSM Version                                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeStaticPasswordHSM ( void          *pHSMContext,
                                                      TDigipassBlob *DPData,
                                                      TKernelParms  *CallParms,
                                                      aat_ascii     *NewStaticPassword1,
                                                      aat_ascii     *NewStaticPassword2);


/*********************************************************************/
/* Change Encrypted Static Password                                  */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeEncryptedStaticPassword ( TDigipassBlob *DPData,
                                                            TKernelParms  *CallParms,
                                                            aat_ascii     *aChallengeIn,
                                                            aat_ascii     *aCESPR);
/*********************************************************************/
/* Change Encrypted Static Password HSM Version                                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeEncryptedStaticPasswordHSM (void          *pHSMContext,
                                                              TDigipassBlob *DPData,
                                                              TKernelParms  *CallParms,
                                                              aat_ascii     *aChallengeIn,
                                                              aat_ascii     *aCESPR);

/*********************************************************************/
/* Change Encrypted Static Password with Enhanced Security           */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeEncryptedStaticPasswordEs ( TDigipassBlob *DPData,
                                                              TKernelParms  *CallParms,
                                                              aat_ascii *aChallengeIn,
                                                              aat_ascii *aCESPR,
                                                              aat_ascii *aServerPublicKey);
/**********************************************************************/
/* Change Encrypted Static Password HSM Version with Enhanced Security*/
/**********************************************************************/
  VDS_EXPORT(aat_int32) AAL2ChangeEncryptedStaticPasswordEsHSM (void        *pHSMContext,
                                                              TDigipassBlob *DPData,
                                                              TKernelParms  *CallParms,
                                                              aat_ascii     *aChallengeIn,
                                                              aat_ascii     *aCESPR,
                                                              aat_ascii     *aServerPublicKey);

/*********************************************************************/
/* Get Information from a Digipass from TDigipassBlob                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GetTokenSingleInfo( TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                TData *DPInfo);

/*********************************************************************/
/* Get Information from a Digipass from TDigipassBlob                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GetTokenInfoEx( TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            TDigipassInfoEx *DPInfo);

/************************************************************************/
/* Synchonise Time drift Information for a Digipass from n TDigipassBlob*/
/************************************************************************/
VDS_EXPORT(aat_int32) AAL2SyncTokenBlobEx(aat_byte       bDPData[8*TDigipassBlobSize],
                                          aat_int16      appl_count,
                                          TKernelParms   *CallParms);

VDS_EXPORT(aat_int32) AAL2SyncTokenBlob(TDigipassBlob *DPData[8],
                                        aat_int16     appl_count,
                                        TKernelParms  *CallParms);

/*************************************************************************/
/* Synchonise Event based or Time based algo for a Digipass TDigipassBlob*/
/*************************************************************************/
  VDS_EXPORT(aat_int32) AAL2SyncTokenAndHost(TDigipassBlob *DPData,
                                             TKernelParms  *CallParms,
                                             aat_ascii     *aResponse1In,
                                             aat_ascii     *aChallenge1In,
                                             aat_ascii     *aResponse2In,
                                             aat_ascii     *aChallenge2In);

  VDS_EXPORT(aat_int32) AAL2SyncTokenAndHostHSM(void          *pHSMContext,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aResponse1In,
                                                aat_ascii     *aChallenge1In,
                                                aat_ascii     *aResponse2In,
                                                aat_ascii     *aChallenge2In);

/*********************************************************************/
/* Migrates a blob from an old set of Derivation Keys to a new one   */
/*********************************************************************/
 VDS_EXPORT(aat_int32) AAL2MigrateBlob (TDigipassBlob*  DPData,
                                        TKernelParms*   CallParms,
                                        aat_int32       DeriveVector,
                                        aat_int32       StorageDeriveKey1,
                                        aat_int32       StorageDeriveKey2,
                                        aat_int32       StorageDeriveKey3,
                                        aat_int32       StorageDeriveKey4);



/*********************************************************************/
/* Generate Keys set and encrypt it with transport Key               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenKeySetHSM( void          *pHSMContext,
                                          aat_ascii     *sw_serial_No,
                                          TKernelParms  *CallParms,
                                          aat_byte      bEncrytedKeySet[160]);

/*********************************************************************/
/* Function uses to change the encryption key of the DIGIPASS Blob   */
/* without changing the values. This is used for changing DB keys or */
/* for changing Transport key to DB key (On line Blob Generation)    */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2MigrateBlobHSM( void          *pHSMContext,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms);

/*********************************************************************/
/* Function uses to change the encryption key of the DIGIPASS Blob   */
/* without changing the values. This is used for changing DB keys or */
/* for changing Transport key to DB key (On line Blob Generation)    */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2MigrateBlobHSMEx( void        *pHSMContext,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *aSessionKeyKCVIn);

/*#ifdef _PKCS11*/
/*********************************************************************/
/* Function used to open an VC HSM Session (PKCS/Thales)             */
/*********************************************************************/

  VDS_EXPORT(aat_int32) AAL2OpenSessionPKCS(void          *pHSMContext,
                                            TKernelParms  *CallParms,
                                            void          *pInitInfo,
                                            aat_ascii     *userID,
                                            aat_ascii     *storageKeyLabel,
                                            aat_ascii     *transportKeyLabel);

/*********************************************************************/
/* This function set session structure parameter (PKCS/Thales)       */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2SetSession( void          *pHSMContext,
                                        TKernelParms  *CallParms,
                                        void          *pInitInfo,
                                        aat_int32     sessionHandle,
                                        aat_ascii     *storageKeyLabel,
                                        aat_ascii     *transportKeyLabel);

/*#endif*/


/*********************************************************************/
/* Function uses to Open an VC HSM Sesssion                          */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2OpenSessionHSM(void          **pHSMContext,
                                           TKernelParms  *CallParms,
                                           void          *InitInfo);

/*********************************************************************/
/* Function uses to Close an VC HSM Sesssion                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2CloseSessionHSM(void *pHSMContext);

/*********************************************************************/
/*Initialize VC HSM Application, has to be called once               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2InitializeHSM(void*pReserved);

/*********************************************************************/
/*Finalize VC HSM Application, has to be called once               */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2FinalizeHSM(void*pReserved);

/*********************************************************************/
/* Generate DIGIPASS Authorisation Code Functions                    */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenUnlockAuthCode(TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_int32     UnlockAuthIndex,
                                              aat_ascii     *aUnlockAuthCode,
                                              aat_int32     *UnlockAuthCounter);

/*********************************************************************/
/* Generate DIGIPASS Authorisation Code Functions                    */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenUnlockAuthCodeHSM(void          *pHSMContext,
                                                 TDigipassBlob *DPData,
                                                 TKernelParms  *CallParms,
                                                 aat_int32     UnlockAuthIndex,
                                                 aat_ascii     *aUnlockAuthCode,
                                                 aat_int32     *UnlockAuthCounter);

/*********************************************************************/
/* Generate Unlock Code after Unlock Authentication Code Validation  */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2AuthorizeUnlock(  TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *aAuthenticationCode,
                                              aat_ascii     *RandomNumber,
                                              aat_ascii     *aUnlockCode);

/*********************************************************************/
/* Generate Unlock Code after Unlock Authentication Code Validation  */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2AuthorizeUnlockHSM(void          *pHSMContext,
                                               TDigipassBlob *DPData,
                                               TKernelParms  *CallParms,
                                               aat_ascii     *aAuthenticationCode,
                                               aat_ascii     *RandomNumber,
                                               aat_ascii     *aUnlockCode);

/*********************************************************************/
/* Set Token Property                                                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2SetTokenProperty( TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_int32     Property,
                                              aat_int32     value);

/*********************************************************************/
/* Get Token Property                                                */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GetTokenProperty( TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_int32      Property,
                                              aat_ascii     *Value);

/*********************************************************************/
/* Synchonise Digipass Event and Blob Event from                     */
/* two concecutive Responses                                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2SyncTokenEvent(TDigipassBlob *DPData,
                                           TKernelParms  *CallParms,
                                           aat_ascii     *aResponse1In,
                                           aat_ascii     *aChallenge1In,
                                           aat_ascii     *aResponse2In,
                                           aat_ascii     *aChallenge2In);

/*********************************************************************/
/* Response Generation Using Kernel Functions                        */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenPassword(TDigipassBlob *DPData,
                                         TKernelParms  *KParms,
                                         aat_ascii     *Password,
                                         aat_ascii     *Challenge);

/*********************************************************************/
/* Response Generation + HostCode generation Using Kernel Functions  */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenPasswordEx(TDigipassBlob *DPData,
                                           TKernelParms  *KParms,
                                           aat_ascii     *Password,
                                           aat_ascii     *Challenge,
                                           aat_ascii     *ReturnHostCode,
                                           aat_int32     *ReturnHostCodeLength);

/*********************************************************************/
/* Response Validation + HostCode generation Using Kernel Functions  */
/*********************************************************************/
VDS_EXPORT(aat_int32)  AAL2GenPasswordHSM(void          *pHSMContext,
                                          TDigipassBlob *DPData,
                                          TKernelParms  *KParms,
                                          aat_ascii     *Password,
                                          aat_ascii     *Challenge,
                                          aat_ascii	    *ReturnHostCode,
                                          aat_int32	    *ReturnHostCodeLength);

/*********************************************************************/
/* Test Response Generation Using Deferred Date                      */
/*********************************************************************/
  VDS_EXPORT(aat_int32) AAL2GenTestPassword(TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *Response,
                                            aat_ascii     *Challenge,
                                            aat_int32      DeferredDate,
                                            aat_ascii     *ReturnHostCode,
                                            aat_int32     *ReturnHostCodeLength);


/*********************************************************************/
/* Signature Generation Using Kernel Functions                       */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenSignature(TDigipassBlob *DPData,
                                          TKernelParms  *KParms,
                                          aat_ascii     *Signature,
                                          aat_ascii     SignedDataFields[8][20],
                                          aat_int32     FieldCount,
                                          aat_int32     DeferredSignatureDate);

/*********************************************************************/
/* Signature Generation + Confirmation Code generation Using Kernel  */
/* Functions                                                         */
/*********************************************************************/
  VDS_EXPORT(aat_int32)  AAL2GenSignatureEx(TDigipassBlob *DPData,
                                            TKernelParms  *KParms,
                                            aat_ascii     *Signature,
                                            aat_ascii     SignedDataFields[8][20],
                                            aat_int32     FieldCount,
                                            aat_int32     DeferredSignatureDate,
                                            aat_ascii     *ConfirmationCode,
                                            aat_int32     *ConfirmationCodeLength);

/*********************************************************************/
/* Signature Generation + Confirmation Code generation Using Kernel  */
/* Functions                                                         */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GenSignatureHSM(void          *pHSMContext,
                                          TDigipassBlob	*DPData,
                                          TKernelParms	*CallParms,
                                          aat_ascii		*Signature,
                                          aat_ascii		SignedDataFields[8][20],
                                          aat_int32		FieldCount,
                                          aat_int32		DeferredSignatureDate,
                                          aat_ascii		*ConfirmationCode,
                                          aat_int32		*ConfirmationCodeLength);

/*********************************************************************/
/* HSM Replacement functions                                         */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GetDerivedKeyHSM( void          *HSMHandle,
                                            TKernelParms  *CallParms,
                                            aat_word32     InputDerivationScheme,
                                            aat_ascii 	  *InputDerivationSeed,
                                            aat_ascii 	  *InputMKName,
                                            aat_int32     *InputMKIndex,
                                            aat_ascii     *InputMKKCV,
                                            aat_ascii     *InputEncryptionKeyName,
                                            aat_int32     *InputEncryptionKeyIndex,
                                            aat_ascii     *InputEncryptionKeyKCV,
                                            aat_ascii     *EncryptedDerivedKey,
                                            aat_ascii     *EncryptedDerivedKeyKCV);

/*********************************************************************/
/* HSM Replacement functions for AAL2GetDerivedKeyHSM                */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GenGetDerivedKeyCmd(aat_byte      *InCmd,
                                              aat_int32     *CmdSize,
                                              TKernelParms  *CallParms,
                                              aat_word32     DerivationScheme,
                                              aat_ascii 	  *DerivationSeed,
                                              aat_ascii 	  *IMKName,
                                              aat_int32     *IMKIndex,
                                              aat_ascii     *IMKKCV,
                                              aat_ascii     *EncryptionKeyName,
                                              aat_int32     *EncryptionKeyIndex,
                                              aat_ascii     *EncryptionKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcGetDerivedKeyRpl( aat_byte     *InReply,
                                                aat_int32     ReplySize,
                                                aat_ascii    *EncryptedDerivedKey,
                                                aat_ascii    *EncryptedDerivedKeyKCV);

/*********************************************************************/
/* HSM Replacement functions for AAL2VerifyPassword                  */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenVerifyPasswordCmd( aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aResponseIn,
                                                aat_ascii     *aChallengeIn);

VDS_EXPORT(aat_int32) AAL2GenVerifyPasswordCmdEx( aat_byte      *InCmd,
                                                  aat_int32     *CmdSize,
                                                  TDigipassBlob *DPData,
                                                  TKernelParms  *CallParms,
                                                  aat_ascii     *aStorageKeyNameIn,
                                                  aat_ascii     *aIVIn,
                                                  aat_ascii     *aResponseIn,
                                                  aat_ascii     *aChallengeIn);

VDS_EXPORT(aat_int32) AAL2ProcVerifyPasswordRpl(aat_byte      *InReply,
                                                aat_int32      ReplySize,
                                                TDigipassBlob *DPData,
                                                aat_ascii     *aReturnHostCodeOut,
                                                aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenerateChallenge               */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenerateChallengeCmd( aat_byte      *InCmd,
                                                   aat_int32     *CmdSize,
                                                   TDigipassBlob *DPData,
                                                   TKernelParms  *CallParms,
                                                   aat_ascii     *aStorageKeyNameIn,
                                                   aat_ascii     *aIVIn);

VDS_EXPORT(aat_int32) AAL2ProcGenerateChallengeRpl( aat_byte      *InReply,
                                                    aat_int32      ReplySize,
                                                    TDigipassBlob *DPData,
                                                    aat_ascii     *aChallengeOut,
                                                    aat_int32     *ChallengeLengthOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenPassword                     */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenPasswordCmd(aat_byte      *InCmd,
                                            aat_int32     *CmdSize,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *aStorageKeyNameIn,
                                            aat_ascii     *aIVIn,
                                            aat_ascii     *aChallengeIn);

VDS_EXPORT(aat_int32) AAL2ProcGenPasswordRpl( aat_byte      *InReply,
                                              aat_int32      ReplySize,
                                              TDigipassBlob *DPData,
                                              aat_ascii     *aResponseOut,
                                              aat_ascii     *aReturnHostCodeOut,
                                              aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenSignature                    */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenSignatureCmd( aat_byte      *InCmd,
                                              aat_int32     *CmdSize,
                                              TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *aStorageKeyNameIn,
                                              aat_ascii     *aIVIn,
                                              aat_ascii      aSignedDataFieldsIn[8][20],
                                              aat_int32      FieldCountIn,
                                              aat_int32      DeferredSignatureDataIn);

VDS_EXPORT(aat_int32) AAL2ProcGenSignatureRpl(aat_byte      *InReply,
                                              aat_int32      ReplySize,
                                              TDigipassBlob *DPData,
                                              aat_ascii     *aResponseOut,
                                              aat_ascii     *aReturnHostCodeOut,
                                              aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM functions for Checking IMK Blob                               */
/*********************************************************************/


VDS_EXPORT(aat_int32) AAL2GenCheckIMKBlobCmd(   aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
												TDigipassBlob *DPData,
                                                TKernelParms  *CallParms);

VDS_EXPORT(aat_int32) AAL2ProcCheckIMKBlobRpl(  aat_byte      *InReply,
                                               aat_int32      ReplySize);


/*********************************************************************/
/* HSM Replacement functions for AAL2VerifyEMVCAPMode1               */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenVerifyEMVCAPMode1Cmd(  aat_byte      *InCmd,
                                                    aat_int32     *CmdSize,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms,
                                                    aat_ascii     *aResponseIn,
                                                    aat_ascii     *aChallengeIn,
                                                    aat_ascii     *aTransactionAmount,
                                                    aat_ascii     *aTransactionCurrency,
                                                    aat_ascii     *aMasterKeyName,
                                                    aat_int32     *MasterKeyID,
                                                    aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcVerifyEMVCAPMode1Rpl( aat_byte      *InReply,
                                                    aat_int32      ReplySize,
                                                    TDigipassBlob *DPData,
                                                    aat_ascii     *aReturnHostCodeOut,
                                                    aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2VerifyEMVCAPMode2               */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenVerifyEMVCAPMode2Cmd(aat_byte      *InCmd,
                                                  aat_int32     *CmdSize,
                                                  TDigipassBlob *DPData,
                                                  TKernelParms  *CallParms,
                                                  aat_ascii     *aSignatureIn,
                                                  aat_ascii      aSignedDataFieldsIn[MAX_EMV_CAP_DATAFIELDS][20],
                                                  aat_int32      TDESFlag,
                                                  aat_ascii     *aMasterKeyName,
                                                  aat_int32     *MasterKeyID,
                                                  aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcVerifyEMVCAPMode2Rpl(aat_byte      *InReply,
                                                   aat_int32      ReplySize,
                                                   TDigipassBlob *DPData,
                                                   aat_ascii     *aReturnHostCodeOut,
                                                   aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2VerifyEMVCAPMode3               */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenVerifyEMVCAPMode3Cmd(  aat_byte      *InCmd,
                                                    aat_int32     *CmdSize,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms,
                                                    aat_ascii     *aResponseIn,
                                                    aat_ascii     *aChallengeIn,
                                                    aat_ascii     *aMasterKeyName,
                                                    aat_int32     *MasterKeyID,
                                                    aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcVerifyEMVCAPMode3Rpl( aat_byte      *InReply,
                                                    aat_int32      ReplySize,
                                                    TDigipassBlob *DPData,
                                                    aat_ascii     *aReturnHostCodeOut,
                                                    aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenEMVCAPMode1                  */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenEMVCAPMode1Cmd(  aat_byte      *InCmd,
                                                 aat_int32     *CmdSize,
                                                 TDigipassBlob *DPData,
                                                 TKernelParms  *CallParms,
                                                 aat_ascii     *aChallengeIn,
                                                 aat_ascii     *aTransactionAmount,
                                                 aat_ascii     *aTransactionCurrency,
                                                 aat_ascii     *aMasterKeyName,
                                                 aat_int32     *MasterKeyID,
                                                 aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcGenEMVCAPMode1Rpl( aat_byte      *InReply,
                                                 aat_int32      ReplySize,
                                                 TDigipassBlob *DPData,
                                                 aat_ascii     *aResponseOut,
                                                 aat_ascii     *aReturnHostCodeOut,
                                                 aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenEMVCAPMode2                  */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenEMVCAPMode2Cmd(aat_byte      *InCmd,
                                               aat_int32     *CmdSize,
                                               TDigipassBlob *DPData,
                                               TKernelParms  *CallParms,
                                               aat_ascii      aSignedDataFieldsIn[MAX_EMV_CAP_DATAFIELDS][20],
                                               aat_int32      TDESFlag,
                                               aat_ascii     *aMasterKeyName,
                                               aat_int32     *MasterKeyID,
                                               aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcGenEMVCAPMode2Rpl(aat_byte      *InReply,
                                                aat_int32      ReplySize,
                                                TDigipassBlob *DPData,
                                                aat_ascii     *aSignatureOut,
                                                aat_ascii     *aReturnHostCodeOut,
                                                aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenEMVCAPMode3                  */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenGenEMVCAPMode3Cmd(  aat_byte      *InCmd,
                                                 aat_int32     *CmdSize,
                                                 TDigipassBlob *DPData,
                                                 TKernelParms  *CallParms,
                                                 aat_ascii     *aChallengeIn,
                                                 aat_ascii     *aMasterKeyName,
                                                 aat_int32     *MasterKeyID,
                                                 aat_ascii     *aMasterKeyKCV);

VDS_EXPORT(aat_int32) AAL2ProcGenEMVCAPMode3Rpl( aat_byte      *InReply,
                                                 aat_int32      ReplySize,
                                                 TDigipassBlob *DPData,
                                                 aat_ascii     *aResponseOut,
                                                 aat_ascii     *aReturnHostCodeOut,
                                                 aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2VerifySignature                 */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenVerifySignatureCmd(aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aSignatureIn,
                                                aat_ascii      aSignedDataFieldsIn[8][20],
                                                aat_int32      FieldCountIn,
                                                aat_int32      DeferredSignatureDataIn);

VDS_EXPORT(aat_int32) AAL2GenVerifySignatureCmdEx(aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aStorageKeyNameIn,
                                                aat_ascii     *aIVIn,
                                                aat_ascii     *aSignatureIn,
                                                aat_ascii      aSignedDataFieldsIn[8][20],
                                                aat_int32      FieldCountIn,
                                                aat_int32      DeferredSignatureDataIn);

VDS_EXPORT(aat_int32) AAL2ProcVerifySignatureRpl(aat_byte      *InReply,
                                                 aat_int32      ReplySize,
                                                 TDigipassBlob *DPData,
                                                 aat_ascii     *aReturnHostCodeOut,
                                                 aat_int32     *ReturnHostCodeLenOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2ChangeStaticPassword            */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenChangeStaticPasswordCmd(aat_byte      *InCmd,
                                                     aat_int32     *CmdSize,
                                                     TDigipassBlob *DPData,
                                                     TKernelParms  *CallParms,
                                                     aat_ascii     *NewStaticPassword1,
                                                     aat_ascii     *NewStaticPassword2);

VDS_EXPORT(aat_int32) AAL2GenChangeStaticPasswordCmdEx(aat_byte      *InCmd,
                                                       aat_int32     *CmdSize,
                                                       TDigipassBlob *DPData,
                                                       TKernelParms  *CallParms,
                                                       aat_ascii     *aStorageKeyNameIn,
                                                       aat_ascii     *aIVIn,
                                                       aat_ascii     *NewStaticPassword1,
                                                       aat_ascii     *NewStaticPassword2);

VDS_EXPORT(aat_int32) AAL2ProcChangeStaticPasswordRpl(aat_byte      *InReply,
                                                      aat_int32      ReplySize,
                                                      TDigipassBlob *DPData);

/*********************************************************************/
/* HSM Replacement functions for AAL2ResetStaticPassword             */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenResetStaticPasswordCmd(aat_byte      *InCmd,
                                                    aat_int32     *CmdSize,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms);

VDS_EXPORT(aat_int32) AAL2GenResetStaticPasswordCmdEx(aat_byte      *InCmd,
                                                      aat_int32     *CmdSize,
                                                      TDigipassBlob *DPData,
                                                      TKernelParms  *CallParms,
                                                      aat_ascii     *aStorageKeyNameIn,
                                                      aat_ascii     *aIVIn);

VDS_EXPORT(aat_int32) AAL2ProcResetStaticPasswordRpl(aat_byte      *InReply,
                                                     aat_int32      ReplySize,
                                                     TDigipassBlob *DPData);

/*********************************************************************/
/* HSM Replacement functions for AAL2Unlock                          */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenUnlockCmd(aat_byte      *InCmd,
                                       aat_int32     *CmdSize,
                                       TDigipassBlob *DPData,
                                       TKernelParms  *CallParms,
                                       aat_ascii     *aRandomNumberIn);

VDS_EXPORT(aat_int32) AAL2GenUnlockCmdEx(aat_byte      *InCmd,
                                         aat_int32     *CmdSize,
                                         TDigipassBlob *DPData,
                                         TKernelParms  *CallParms,
                                         aat_ascii     *aStorageKeyNameIn,
                                         aat_ascii     *aIVIn,
                                         aat_ascii     *aRandomNumberIn);

VDS_EXPORT(aat_int32) AAL2ProcUnlockRpl(aat_byte      *InReply,
                                        aat_int32      ReplySize,
                                        TDigipassBlob *DPData,
                                        aat_ascii     *aUnlockCodeOut,
                                        aat_int32      UnlockCodeLenIn);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenUnlockAuthCode               */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenUnlockAuthCodeCmd(aat_byte      *InCmd,
                                               aat_int32     *CmdSize,
                                               TDigipassBlob *DPData,
                                               TKernelParms  *CallParms,
                                               aat_int32      UnlockAuthIndex);

VDS_EXPORT(aat_int32) AAL2GenUnlockAuthCodeCmdEx(aat_byte      *InCmd,
                                                 aat_int32     *CmdSize,
                                                 TDigipassBlob *DPData,
                                                 TKernelParms  *CallParms,
                                                 aat_ascii     *aStorageKeyNameIn,
                                                 aat_ascii     *aIVIn,
                                                 aat_int32      UnlockAuthIndex);

VDS_EXPORT(aat_int32) AAL2ProcUnlockAuthCodeRpl(aat_byte      *InReply,
                                                aat_int32      ReplySize,
                                                TDigipassBlob *DPData,
                                                aat_ascii     *aUnlockAuthCodeOut,
                                                aat_word32     UnlockAuthCodeLenIn,
                                                aat_int32     *UnlockAuthCounterOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2AuthorizeUnlock                 */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenAuthorizeUnlockCmd(aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aUnlockAuthCodeIn,
                                                aat_ascii     *aRandomNumberIn);

VDS_EXPORT(aat_int32) AAL2GenAuthorizeUnlockCmdEx(aat_byte      *InCmd,
                                                aat_int32     *CmdSize,
                                                TDigipassBlob *DPData,
                                                TKernelParms  *CallParms,
                                                aat_ascii     *aStorageKeyNameIn,
                                                aat_ascii     *aIVIn,
                                                aat_ascii     *aUnlockAuthCodeIn,
                                                aat_ascii     *aRandomNumberIn);

VDS_EXPORT(aat_int32) AAL2ProcAuthorizeUnlockRpl(aat_byte      *InReply,
                                                 aat_int32      ReplySize,
                                                 TDigipassBlob *DPData,
                                                 aat_ascii     *aUnlockCodeOut,
                                                 aat_int32      UnlockCodeLenIn);

/*********************************************************************/
/* HSM Replacement functions for AAL2SyncTokenAndHost                */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenSyncTokenAndHostCmdEx( aat_byte      *InCmd,
                                                    aat_int32     *CmdSize,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms,
                                                    aat_ascii     *aStorageKeyNameIn,
                                                    aat_ascii     *aIVIn,
                                                    aat_ascii     *aResponseIn,
                                                    aat_ascii     *aChallengeIn,
                                                    aat_ascii     *aResponse2In,
                                                    aat_ascii     *aChallenge2In);


VDS_EXPORT(aat_int32) AAL2GenSyncTokenAndHostCmd( aat_byte      *InCmd,
                                                  aat_int32     *CmdSize,
                                                  TDigipassBlob *DPData,
                                                  TKernelParms  *CallParms,
                                                  aat_ascii     *aResponseIn,
                                                  aat_ascii     *aChallengeIn,
                                                  aat_ascii     *aResponse2In,
                                                  aat_ascii     *aChallenge2In);

VDS_EXPORT(aat_int32) AAL2ProcSyncTokenAndHostRpl(aat_byte      *InReply,
                                                  aat_int32      ReplySize,
                                                  TDigipassBlob *DPData);

/*********************************************************************/
/* HSM Replacement functions for AAL2MigrateBlob                     */
/*********************************************************************/

VDS_EXPORT(aat_int32) AAL2GenMigrateBlobCmd(aat_byte      *InCmd,
                                            aat_int32     *CmdSize,
                                            TDigipassBlob *DPData,
                                            TKernelParms  *CallParms);

VDS_EXPORT(aat_int32) AAL2GenMigrateBlobCmdEx(aat_byte      *InCmd,
                                              aat_int32     *CmdSize,
                                              TDigipassBlob *DPData,
                                              TKernelParms  *CallParms,
                                              aat_ascii     *aDecryptionKeyNameIn,
                                              aat_ascii     *aDecryptionIVIn,
                                              aat_ascii     *aSK_KCV,
                                              aat_ascii     *aEncryptionKeyNameIn,
                                              aat_ascii     *aEncryptionIVIn);

VDS_EXPORT(aat_int32) AAL2ProcMigrateBlobRpl(aat_byte      *InReply,
                                             aat_int32      ReplySize,
                                             TDigipassBlob *DPData);




  VDS_EXPORT(aat_int32) AAL2TestGenPassword(TDigipassBlob *DPData,
                                            TKernelParms  *CallParms,
                                            aat_ascii     *Response,
                                            aat_ascii     *Challenge,
                                            aat_int32      DeferredDate,
                                            aat_ascii     *ReturnHostCode,
                                            aat_int32     *ReturnHostCodeLength);

  VDS_EXPORT(aat_int32) AAL2GenHashDataBlock(TDigipassBlob *DPData,
                                             TKernelParms  *CallParms,
                                             aat_int32		EventWindow,
                                             aat_int32		StartTime,
                                             aat_int32		EndTime,
                                             aat_byte		*Salt,
                                             aat_int32		SaltLength,
                                             aat_word32		MaxRadomValue,
                                             aat_byte		*bKey,
                                             aat_int32		KeyLength,
                                             aat_byte		*bHashDataBlock,
                                             aat_int32		*HashDataBlockLength);

VDS_EXPORT(aat_int32)  AAL2SyncStateData(
                            TDigipassBlob	*DPData,
                            TKernelParms	*CallParms,
                            aat_byte	    *bStateDataBlock,
                            aat_int32	    StateDataBlockLength);

VDS_EXPORT(aat_int32)  AAL2GetStateDataBlock(
                                TDigipassBlob	*DPData,
                                TKernelParms	*CallParms,
                                aat_byte	    *bStateDataBlock,
                                aat_int32	    *StateDataBlockLength );

VDS_EXPORT(aat_int32) VerifyPassword
(
TKernelParms		*CallParms,
aat_ascii		    *aPassword,
aat_byte		    *bSalt,
aat_int32		    SaltLength,
aat_byte		    *bStateDataBlock,
aat_int32		    StateDataBlockLength,
aat_byte		    *bHashDataBlock,
aat_int32		    HashDataBlockLength,
aat_byte		    *bKey,
aat_int32		    *KeyLength);


/*********************************************************************/
/* Functions used for DP4WEB                                         */
/*********************************************************************/

VDS_EXPORT(aat_int32)AAL2QAGenQABlob(    aat_int32       QANb,
                                         aat_ascii       *aQAList,
                                         aat_ascii       *aUserID,
                                         aat_ascii       *aQABlob,
                                         aat_int32       *QABlobSize);

VDS_EXPORT(aat_int32)AAL2QAGenQAHashData( aat_ascii       *aQABlob,
                                          aat_int32       SecurityLevel,
                                          aat_ascii       *aQAIndexList,
                                          aat_ascii       *aQAHashData);

VDS_EXPORT(aat_int32)AAL2QADecryptQABlob( TDigipassBlob   *DPData,
                                          TKernelParms    *CallParms,
                                          aat_ascii       *Challenge,
                                          aat_ascii       *aEncryptedQABlob,
                                          aat_ascii       *aQABlob,
                                          aat_int32       *QABlobSize);

VDS_EXPORT(aat_int32)AAL2QADecryptQABlobHSM(void            *pHSMContext,
                                            TDigipassBlob   *DPData,
                                            TKernelParms    *CallParms,
                                            aat_ascii       *Challenge,
                                            aat_ascii       *aEncryptedQABlob,
                                            aat_ascii       *aQABlob,
                                            aat_int32       *QABlobSize);

VDS_EXPORT(aat_int32)AAL2GenActivationCodeEx( TDigipassBlob   *DPData,
                                              TKernelParms    *CallParms,
                                              aat_ascii       *aStaticVectorIn,
                                              aat_ascii       *aSharedData,
                                              aat_ascii       *aAlea,
                                              aat_int32       *ActivationCodeFormat,
                                              aat_ascii       *aSerialNumberSuffix,
                                              aat_ascii       *aXFAD);

VDS_EXPORT(aat_int32)AAL2GenActivationCodeExHSM(void            *pHSMContext,
                                                TDigipassBlob   *DPData,
                                                TKernelParms    *CallParms,
                                                aat_ascii       *aStaticVectorIn,
                                                aat_ascii       *aSharedData,
                                                aat_ascii       *aAlea,
                                                aat_int32       *ActivationCodeFormat,
                                                aat_ascii       *aSerialNumberSuffix,
                                                aat_ascii       *aXFAD);

VDS_EXPORT(aat_int32)AAL2GenActivationCodeXErc(	TDigipassBlob   *DPData [8],
                             					aat_int16        Appl_count,
												TKernelParms    *CallParms,
												aat_ascii       *aStaticVectorIn,
												aat_ascii       *aSharedData,
												aat_ascii       *aAlea,
												aat_int32       *ActivationCodeFormat,
												aat_ascii       *aSerialNumberSuffix,
												aat_ascii       *aXFAD,
												aat_ascii       *aXERC);

/* use for dotnet wrapper only*/
VDS_EXPORT(aat_int32) AAL2GenActivationCodeXErcEx(aat_byte       bDPData[8*TDigipassBlobSize],
												  aat_int16		 Appl_Count,
                                          		  TKernelParms    *CallParms,
	                                      		  aat_ascii       *aStaticVectorIn,
	                                      		  aat_ascii       *aSharedData,
	                                      		  aat_ascii       *aAlea,
	                                      		  aat_int32       *ActivationCodeFormat,
	                                      		  aat_ascii       *aSerialNumberSuffix,
	                                      		  aat_ascii       *aActivationCode,
										  		  aat_ascii       *aXERC);

VDS_EXPORT(aat_int32)AAL2GenActivationCodeXErcHSM(	void            *pHSMContext,
													TDigipassBlob   *DPData [8],
                             						aat_int16        Appl_count,
													TKernelParms    *CallParms,
													aat_ascii       *aStaticVectorIn,
													aat_ascii       *aSharedData,
													aat_ascii       *aAlea,
													aat_int32       *ActivationCodeFormat,
													aat_ascii       *aSerialNumberSuffix,
													aat_ascii       *aXFAD,
													aat_ascii       *aXERC);

VDS_EXPORT(aat_int32)AAL2GenQAKey( aat_ascii       *aQAIndexList,
                                   aat_ascii       *aQAHashData,
                                   aat_ascii       *aUserID,
                                   aat_ascii       aQAKey[33]);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenActivationCodeEx             */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GenGenActivationCodeExCmd(aat_byte      *InCmd,
                                                    aat_int32     *CmdSize,
                                                    TDigipassBlob *DPData,
                                                    TKernelParms  *CallParms,
                                                    aat_ascii     *aStorageKeyNameIn,
                                                    aat_ascii     *aIVIn,
	                                                aat_ascii     *aStaticVectorIn,
	                                                aat_ascii     *aSharedData,
	                                                aat_ascii     *aAlea,
	                                                aat_int32     *ActivationCodeFormat);


VDS_EXPORT(aat_int32) AAL2ProcGenActivationCodeExRpl( aat_byte      *InReply,
                                                      aat_int32      ReplySize,
                                                      TDigipassBlob *DPData,
                                                      aat_int32     *ActivationCodeFormat,
                                                      aat_ascii     *aSerialNumberSuffixOut,
                                                      aat_ascii     *aXFADOut);

/*********************************************************************/
/* HSM Replacement functions for AAL2GenActivationCodeXErc           */
/*********************************************************************/

VDS_EXPORT(aat_int32)AAL2GenGenActivationCodeXErcCmd(	aat_byte        *InCmd,
														aat_int32       *CmdSize,
														TDigipassBlob   *DPData [8],
                             							aat_int16        Appl_count,
														TKernelParms    *CallParms,
														aat_ascii		*aStorageKeyNameIn,
														aat_ascii		*aIVIn,
														aat_ascii       *aStaticVectorIn,
														aat_ascii       *aSharedData,
														aat_ascii       *aAlea,
														aat_int32       *ActivationCodeFormat,
														aat_int32       XERCFlag);

VDS_EXPORT(aat_int32)AAL2ProcGenActivationCodeXErcRpl(  aat_byte      *InReply,
														aat_int32      ReplySize,
														TDigipassBlob *DPData[8],
														aat_int32     *ActivationCodeFormat,
														aat_ascii     *aSerialNumberSuffixOut,
														aat_ascii     *aXFADOut,
														aat_ascii     *aXERCOut);


/* use for dotnet wrapper only*/
VDS_EXPORT(aat_int32)AAL2GenGenActivationCodeXErcExCmd(	aat_byte        *InCmd,
														aat_int32       *CmdSize,
														aat_byte         bDPData[8*TDigipassBlobSize],
                             							aat_int16        Appl_count,
														TKernelParms    *CallParms,
														aat_ascii		*aStorageKeyNameIn,
														aat_ascii		*aIVIn,
														aat_ascii       *aStaticVectorIn,
														aat_ascii       *aSharedData,
														aat_ascii       *aAlea,
														aat_int32       *ActivationCodeFormat,
														aat_int32       XERCFlag);

/* use for dotnet wrapper only*/
VDS_EXPORT(aat_int32)AAL2ProcGenActivationCodeXErcExRpl(aat_byte      *InReply,
														aat_int32      ReplySize,
														aat_byte       bDPData[8*TDigipassBlobSize],
														aat_int32     *ActivationCodeFormat,
														aat_ascii     *aSerialNumberSuffixOut,
														aat_ascii     *aXFADOut,
														aat_ascii     *aXERCOut);


/*********************************************************************/
/* HSM Replacement functions for AAL2QADecryptQABlob                 */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GenQADecryptQABlobCmd(aat_byte	  *InCmd,
											    aat_int32	  *CmdSize,
												TDigipassBlob *DPBlob,
												TKernelParms  *CallParms,
												aat_ascii	  *aStorageKeyNameIn,
												aat_ascii	  *aIVIn,
                                                aat_ascii     *aChallenge,
                                                aat_ascii     *aEncryptedQABlob );

VDS_EXPORT(aat_int32) AAL2ProcQADecryptQABlobRpl(   aat_byte      *InReply,
                                                    aat_int32      ReplySize,
                                                    TDigipassBlob *DPDBlob,
                                                    aat_ascii     *aQABlobOut,
                                                    aat_int32     *QABlobSizeOut);

/*********************************************************************/
/* Generate Digipass Blob From TLV                                   */
/*********************************************************************/
VDS_EXPORT(aat_int32) AAL2GenDPBlobHSM(void           *pHSMContext,
                                       TDigipassBlob  *DPData,
                                       TKernelParms   *CallParms,
                                       aat_ascii       DPSerial[22],
                                       aat_ascii      *AuthMode,
                                       aat_ascii      *MasterKeyLabel,
                                       aat_ascii      *MasterKeyKCV,
                                       aat_ascii      *DerivationSeed,
                                       aat_ascii      *DerivationKeyKCV,
                                       aat_word32      DerivationAlgo,
                                       aat_byte       *TLVData,
                                       aat_int32       nTLVDataLength);

#ifdef __cplusplus
}
  #endif

#endif /* AAL2SDK_H */

