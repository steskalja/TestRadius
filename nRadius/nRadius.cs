using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections;
using System.Net.nRadius;
using Gurock.SmartInspect;


/**********************************************************************************************
 **     Radius Client by Nightwalker_z 
 **     Version 1.0 - Build 2007040
 **     * added timeout for udp connection (10 seconds)
 ** 
 **     REVISION LOG:
 **     Version 1.1 - Build 071123
 **     + added a new class just for Radius Attributes (RadiusAttribute)
 **     + added an utility class for non-radius jobs
 **     + added support for any Radius attribute, using the nRadius.SetAttribute Method
 **
 **     Version 1.0 - Build 071122
 **     + able to set UPD timeout with property radius_client.UDPTimeout 
 **       Default value are 5 seconds.
 **********************************************************************************************/

namespace System.Net.nRadius
{
    public class nRadius_Client
    {
        private const int UDP_TTL = 20;
        
        // Put all the Radius Attributes in a list (pAttributeList)
        ArrayList pAttributeList = new ArrayList();
        
        private string pSSecret = null; //Shared Secret
        private string pUsername = null;
        private string pPassword = null;
        private string pMessage = null;
        private string pServer = null;
        private int pRadiusPort = 1812;
        private int pUDPTimeout = 5;

        private bool pDebug = false;

        private byte[] pRA = new byte[16];
        private int pClientIdentifier;

        
        /* Constructor */
        public nRadius_Client(string Server, string SharedSecret, string Username, string Password)
        {
            pServer = Server;
            pSSecret = SharedSecret;
            pUsername = Username;
            pPassword = Password;
            if(SiAuto.Si.Level == Level.Debug)
            {
                pDebug = true;
            }
           
        } // public radius_client()

        // Properties
        public string SharedSecret
        {
            set { pSSecret = value; }
            get { return pSSecret; }
        } // public string SharedSecret
        public string UserName
        {
            set { pUsername = value; }
            get { return pUsername; }
        } // public string UserName
        public string Password
        {
            set { pPassword = value; }
            get { return pPassword; }
        } // public string Password
        public string Server
        {
            set { pServer = value; }
            get { return pServer; }
        } // public string Server
        public int Port
        {
            set { pRadiusPort = value; }
            get { return pRadiusPort; }
        } // public int Port

        public int UDPTimeout
        {
            set { pUDPTimeout = value; }
            get { return pUDPTimeout; }
        } //public int UDPTimeout

        public string Response
        {
            get { return pMessage; }
        }
        public bool Debug
        {
            get { return pDebug;  }
        }
        
        // Method
        public int Authenticate()
        {
            DebugOutput("Shared Secret (S): " + pSSecret);
            DebugOutput("Username: " + pUsername);
            //DebugOutput("Password: " + pPassword + " (" + pPassword.Length*8 + " bits)");

            /* Aufbau eines Radius Paketes
             * 0                   1                   2                   3
             * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * |     Code      |  Identifier   |            Length             |
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * |                                                               |
             * |                         Authenticator                         |
             * |                                                               |
             * |                                                               |
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * |  Attributes ...
             * +-+-+-+-+-+-+-+-+-+-+-+-+-
             * 
             * 
             * CODE (1 byte): 
             *  The type of the Radius Paket.
             *  Pakets with an invalid code will be discarded.
             *    1 = Access-Request
             *    2 = Access-Accept
             *    3 = Access-Reject
             *   11 = Access-Challenge
             *   12 = Status-Server (exp.)
             *   13 = Status-Client (exp.)
             *  255 = reserved
             * 
             * IDENTIFIER (1 byte):
             *  Is the same in Request and Reply.
             *  (Random Number from 1..254)
             * 
             * LENGTH (2 byte):
             *  Length of the paket in BYTE over:
             *  Code, Identifier, Length, Authenticator and Attribute(s)
             *  - Bytes which excess the length, will be cut.
             *  - Pakets smaller then the length will be discarded by the server.
             * 
             * AUTHENTICATOR (16 byte):
             *  16-byte random number 
             *  Used for the encryption of the user-password
             * 
             * ATTRIBUTES (dynamic length):
             *  0                   1                   2
             *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
             * |      Type     |    Length     |  Value ...
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
             * 
             *  - User Password = Type 2 (String)
             *  A complete Attribute-List: http://www.freeradius.org/rfc/attributes.html
             * 
             * */

            byte pCode = 1; // Access-Request
            int pResult = 0;

            Random pRandonNumber = new Random();
            byte pIdentifier = Convert.ToByte(pRandonNumber.Next(0, 32000) % 256);
            pClientIdentifier = pIdentifier;
            DebugOutput("Identifier (Radius-Request): " + pClientIdentifier);
            GenerateRA(); //Should be a random number!!!
            DebugOutput("Request Authenticator (RA): " + Utils.ToHexString(pRA));
                        
            // Assemble Attribute User-Name (Type = 1) and put it in the list
            SetAttribute(1, pUsername);

            // Assemble Attribute User-Password (Type = 2) and put it in the list
            SetAttribute(2, Crypto.GeneratePAP_PW(pPassword, pSSecret, pRA));
                                
            // Assemble complete Radius Paket:
            // 1.) Determine the length of the paket (in bytes)
            //     Code, ID & Lenght = 4 Bytes
            //******************************************************************************
            int pAttrLength = 0;
            foreach (RadiusAttribute pCurrAttr in pAttributeList)
            {
                pAttrLength += pCurrAttr.Paket.Length;
            } //foreach (RadiusAttribute pCurrAttr in pAttributeList)

            int pLength = 4 + pRA.Length + pAttrLength;
            //******************************************************************************
            int pOffset = 0;
            // 2.) Creating empty byte Array with the calculated length
            byte[] pRadiusPaket = new byte[pLength];

            // 3.) Copy the paket-parts to the paket
            // 3.1) the Code from pCode
            pRadiusPaket[0] = pCode;

            // 3.2) The identifier from pIdentifier
            pRadiusPaket[1] = pIdentifier;
            pOffset = 1;

            // 3.3) The paket length (2 Byte)
            // ENDIANESS PROBLEM !!! CAUTION
            byte[] pPacketLen = Utils.intToByteArray(pLength);
            Array.Copy(pPacketLen, 0, pRadiusPaket, pOffset + 1, 2);
            pOffset = pOffset + 2;
            
            // 3.4) The RA from pRA            
            //Array.Copy(System.Text.Encoding.ASCII.GetBytes(pRA), 0, pRadiusPaket, pOffset + 1, pRA.Length);
            Array.Copy(pRA, 0, pRadiusPaket, pOffset + 1, pRA.Length);
            pOffset = pOffset + pRA.Length;

            // 3.5) Add Radius Attributes to Paket
            foreach (RadiusAttribute pCurrAttr in pAttributeList)
            {
                Array.Copy(pCurrAttr.Paket, 0, pRadiusPaket, pOffset + 1, pCurrAttr.Paket.Length);
                pOffset += pCurrAttr.Paket.Length;
            }
                        
            // SENDING THE PAKET TO THE REMOTE RADIUS SERVER
            try
            {
                System.Net.Sockets.UdpClient myRadiusClient = new System.Net.Sockets.UdpClient();
                myRadiusClient.Client.SendTimeout = pUDPTimeout;
                myRadiusClient.Client.ReceiveTimeout = UDPTimeout;
                DebugOutput("Trying to send the Radius-Request to " + pServer + ":" + pRadiusPort.ToString());

                myRadiusClient.Ttl = UDP_TTL;
                myRadiusClient.Connect(pServer, pRadiusPort);
                myRadiusClient.Send(pRadiusPaket, pRadiusPaket.Length);
                                                                
                System.Net.IPEndPoint RemoteIpEndPoint = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                Byte[] receiveBytes = myRadiusClient.Receive(ref RemoteIpEndPoint);
                
                myRadiusClient.Close();
                pResult = ProcessServerResponse(receiveBytes);
                //DebugOutput("Output by ProcessServerResponse: " + Code2Message(pResult) + " (Code = " + pResult.ToString() + ")");
            }

            catch (Exception e)
            {
                DebugOutput("Exception Error: " + e.ToString());
                pMessage = "Exception Error: " + e.Message;
                SiAuto.Main.LogError(e.Message);
                return -2;
            }
            return pResult;
        } //public int Authenticate()

        private void GenerateRA()
        {
            Random pRandonNumber = new Random();
            for (int i = 0; i < 15; i++)
            {
                pRA[i] = Convert.ToByte(1 + pRandonNumber.Next() % 255);
                pRandonNumber.Next();
            } //for (int i = 0; i < 15; i++)
        } //private void GenerateRA()

        
        public void SetAttribute(byte Type, string Value)
        {
            if (AttributeExists(Type) != -1)
                RemoveAttribute(Type);

            RadiusAttribute pRadiusAttribute = new RadiusAttribute(Type, Value);
            if (pRadiusAttribute.Index != 0)
            {
                pAttributeList.Add(pRadiusAttribute);
                DebugOutput("Adding Radius Attribute Type " + Type + " (" + pRadiusAttribute.Name + ") " +
                            "with value " + Value);
            }
            else
                DebugOutput("ERROR: Attribute Type " + Type + " (" + pRadiusAttribute.Name + ") " +
                            "with value " + Value + " could not be added - parsing error");
        } //public void AddAttribute(byte Type, string Value)

        
        private void SetAttribute(byte Type, byte[] Value)
        {
            if (AttributeExists(Type) != -1)
                RemoveAttribute(Type);

            
            RadiusAttribute pRadiusAttribute = new RadiusAttribute(Type, Value);
            pAttributeList.Add(pRadiusAttribute);
            DebugOutput("Adding Radius Attribute Type " + Type + " (" + pRadiusAttribute.Name + ") " +
                        "with value " + Utils.ToHexString(Value));

        } //public void AddAttribute(byte Type, string Value)
        
          
        public bool RemoveAttribute(byte Type)
        {
            bool pRemoved = false;
            DebugOutput("Trying to remove Attribute " + Type + " from Attribute list ... ");
            int pAttrPos = AttributeExists(Type);

            if (pAttrPos != -1)
            {
                pAttributeList.RemoveAt(pAttrPos);
                pRemoved = true;
                DebugOutput("  ... found Attribute at position " + pAttrPos.ToString() + " and deleted it");
            } //if (pAttrPos != -1)
            else
                DebugOutput("  ... could not find Attribute in the list - there's nothing to do");

            return pRemoved;
        } //public void RemoveAttribute(byte Type)

        public int AttributeExists(byte Type)
        {
            int pFoundPos = -1;
            int x = 0;

            while (x != pAttributeList.Count && pFoundPos == -1)
            {
                if (((RadiusAttribute)pAttributeList[x]).Index == Type)
                {
                    pFoundPos = x;
                }
                x++;
            } //while (x != pAttributeList.Count)

            return pFoundPos;
        } //public bool AttributeExists(byte Type)
        
        private int ProcessServerResponse(byte[] receivedBytes)
        {
            // Processing of received Radius Paket
            // ####################################################################################
            int pPaketLen = receivedBytes.Length;
            int pReturn = 0; //0 means everything is OK
            int pCode = 0; 
            int pIdentifier = 0;
            int pLen = 0;
            bool pErrorOccured = false;
            
         

            // 1. Case: No packet data (no received data) --> Communication error
            if (pPaketLen == 0)
            {
                pReturn = -1;
                pMessage = "No packet data (no received data)";
            }
            else if (pPaketLen >= 20) // there is packet data
            {   // ##########################################################################################
                // Checking the Radius Code (first Bit) and the minimum packet length of 20 bytes
                    pCode = receivedBytes[0];
                    DebugOutput("Code (Radius-Response): " + pCode.ToString());
                    switch (pCode)
                    {
                        case 2:
                            {
                                pReturn = 0;
                                pMessage = "Access Accepted";
                            }
                            break;
                        case 3:
                            {
                                pReturn = -4;
                                pMessage = "Access Rejected";
                            }
                            break;
                        case 11:
                            {
                                pReturn = -8;
                                pMessage = "Access Challenged";
                            }
                            break;
                    } 


                // ##########################################################################################
                // Checking Radius identifier. The request identifier (pClientIdentifier) must be equal to
                // the response identifier of the radius server.
                if (pPaketLen>=20 && !pErrorOccured)
                {
                    pIdentifier = receivedBytes[1];
                    DebugOutput("Identifier (Radius-Response): " + pIdentifier.ToString());
                    if (pIdentifier != pClientIdentifier)
                    {
                        pReturn = -5;
                        pMessage = "The request identifier does not match the response identifier";
                        pErrorOccured = true;
                    }
                }


                // ##########################################################################################
                // Checking the length field of the packet. This value must be equal to the byteArray length
                // "receivedBytes.Length"
                if (pPaketLen >= 20 && !pErrorOccured)
                {
                    pLen = receivedBytes[2] + receivedBytes[3];
                    DebugOutput("Packet Length (Radius-Response): " + pLen.ToString());
                    if (pLen != pPaketLen)
                    {
                        pReturn = -6;
                        pMessage = "The packet length does not match the byte array length";
                        pErrorOccured = true;
                    }
                }

                // ##########################################################################################
                // Checking the Response Authenticator (bytes 4-20)
                // The Response Authenticator must be equal to the following:
                // MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
                // NOT WORKING YET !!!!

                if (pPaketLen >= 20 && !pErrorOccured)
                {
                    // Calculating Response Authenticator
                    /*
                    string pRespAuthString_Calculated = 2 + pIdentifier.ToString() + "60" +
                                                        Encoding.Default.GetString(pRA) +
                                                        Encoding.Default.GetString(GetAttr_Username()) +
                                                        Encoding.Default.GetString(GetAttr_Password()) +
                                                        Encoding.Default.GetString(GetAttr_NASIP()) +
                                                        pSSecret;
                 

                    // Creating the MD5Sum of the calculated Response Authenticator
                    MD5 md5 = new MD5CryptoServiceProvider();
                    byte[] pMD5RespAuth_Calc = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(pRespAuthString_Calculated));
                    DebugOutput("Calculated Response Authenticator (Radius-Response): " + ToHexString(pMD5RespAuth_Calc));
                    string temp1 = ToHexString(pMD5RespAuth_Calc);

                    // Getting the Response Authenticator from the received Packet
                    byte[] temp = new byte[16];
                    Array.Copy(receivedBytes, 4, temp, 0, 16);

                    byte[] pMD5RespAuth_Data = md5.ComputeHash(temp);
                    DebugOutput("Received Response Authenticator (Radius-Response): " + ToHexString(pMD5RespAuth_Data));
                    string temp2 = ToHexString(pMD5RespAuth_Data);
                     */
                    
                }
                

            }
            else if(pPaketLen > 0 & pPaketLen < 20)
            {
                pReturn = -3;
                pMessage = "Packet size is less than 20 bytes, please try again";
                pErrorOccured = true;
            }

            return pReturn;
        } //private int ProcessServerResponse(byte[] receivedBytes)

        



        private void DebugOutput(string Output)
        {
            if (pDebug)
            {
                SiAuto.Main.LogDebug(Output);
            }
            
        }

        


    }

    
    

}
