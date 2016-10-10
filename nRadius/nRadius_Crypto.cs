using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace System.Net.nRadius
{
    internal static partial class Crypto
    {
        public static byte[] GeneratePAP_PW(string ClearTextPW, string SharedSecret, byte[] RequestAuthenticator)
        {
            /* Generates the Encrypted Password (c) for the data paket 
             * 1.) Split the userpassword (P) in 128 bit / 16 byte blocks (p1 .. pn)
             *     if the last block is not devidable by 16, pad it with "0"
             * 2.) XOR these Blocks with the MD5 of the SharedSecret (S) and the Request Authenticator (RA)
             *     c1 = p1 XOR MD5(S + RA)
             *     c2 = p2 XOR MD5(S + c1)
             *     cn = pn XOR MD5(S + cn-1)
             *     
             *     c  = c1 + c2 + ... + cn (Concat)
             * 
             */

            // Initially the MD5 is taken over the Shared Secret and the Request Authenticator
            string pKeyRA = SharedSecret + Encoding.Default.GetString(RequestAuthenticator);
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] pMD5Sum = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(pKeyRA));
            string pMD5String = Utils.ToHexString(pMD5Sum);

            // Determine how many rounds are needed for authentication
            int pCrounds = ClearTextPW.Length / 16;
            if (ClearTextPW.Length % 16 != 0) { pCrounds++; }


            byte[] Result = new byte[pCrounds * 16];
            for (int j = 0; j < pCrounds; j++)
            {
                int pm;
                int pp;

                //Split the password in 16byte chunks
                string pRoundPW = "";
                if (ClearTextPW.Length < (j + 1) * 16) { pRoundPW = ClearTextPW.Substring(j * 16, ClearTextPW.Length - j * 16); }
                else { pRoundPW = ClearTextPW.Substring(j * 16, 16); }

                for (int i = 0; i <= 15; i++)
                {
                    if (2 * i > pMD5String.Length) { pm = 0; } else { pm = System.Convert.ToInt32(pMD5String.Substring(2 * i, 2), 16); }
                    if (i >= pRoundPW.Length) { pp = 0; } else { pp = (int)pRoundPW[i]; }
                    int pc = pm ^ pp;
                    Result[(j * 16) + i] = (byte)pc;
                } //for (int i = 0; i <= 15; i++)


                //Determine the next MD5 Sum MD5(S + cn-1)
                byte[] pCN1 = new byte[16];
                Array.Copy(Result, j * 16, pCN1, 0, 16);
                string pKeyCN1 = SharedSecret + Encoding.Default.GetString(pCN1);
                md5 = new MD5CryptoServiceProvider();
                pMD5Sum = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(pKeyCN1));
                pMD5String = Utils.ToHexString(pMD5Sum);
            }

            return Result;
        }

        public static byte[] CalcResponseAuth(byte[] ReceivedBytes)
        {
            byte[] temp = new byte[3];



            return temp;
        } //public static byte[] CalcResponseAuth(byte[] ReceivedBytes)
        

    } //internal static partial class Crypto
}
