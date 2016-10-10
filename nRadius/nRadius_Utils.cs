
namespace System.Net.nRadius
{
    /****************************************************************************************
     * Class: Utils                                                                         *
     ****************************************************************************************
     * The class Utils contains some small utilities needed for the Radius class            *
     * These Utils have typically nothing to do with radius. They are here to get f.e       *
     * the current IP adress of this client ... etc.                                        *
     ***************************************************************************************/
    internal static partial class Utils
    {
        public static IPAddress GetCurrentIP()
        {
            //IPAddress pIP = new IPAddress
            byte[] IPBytes = new byte[4];
            string HostName = System.Net.Dns.GetHostEntry("127.0.0.1").HostName;
            IPHostEntry local = System.Net.Dns.GetHostEntry(HostName);

            if (local.AddressList.Length > 0)
            {
                IPBytes = local.AddressList[0].GetAddressBytes();
            }
            else
            {
                IPBytes = IPAddress.Loopback.GetAddressBytes();
            }

            IPAddress returnIP = new IPAddress(IPBytes);
            return returnIP;
        } //public static IPAddress GetCurrentIP()

        public static string ToHexString(byte[] bytes)
        {
            
            char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7',
                                 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

            
            char[] chars = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int b = bytes[i];
                chars[i * 2] = hexDigits[b >> 4];
                chars[i * 2 + 1] = hexDigits[b & 0xF];
            }
            return new string(chars);
        } //public static string ToHexString(byte[] bytes)

        public static byte[] intToByteArray(int value)
        {
            byte[] littleendian = BitConverter.GetBytes((short)value);
            return new byte[] { littleendian[1], littleendian[0] };
        } //public static byte[] intToByteArray(int value)

        public static string Code2Message(int MessageCode)
        /**********************************************************
         * This function converts an integer value to a human     *
         * readable (error)message                                *              
         **********************************************************/
        {
            string pReturn = "";
            switch (MessageCode)
            {
                case 0: pReturn = "Authentication successful";
                    break;
                case -1: pReturn = "Communication trouble. Is the server reachable? Maybe the shared secret is wrong";
                    break;
                case -2: pReturn = "Communication trouble. The remote host refused the connection (maybe a timeout)";
                    break;
                case -3: pReturn = "Paket length from the server is too small. Minimum is 20 bytes";
                    break;
                case -4: pReturn = "The server rejected you authentication request";
                    break;
                case -5: pReturn = "The response identifier does not match the request identifier";
                    break;
                case -6: pReturn = "The paket length from the server is incorrect";
                    break;

                default: pReturn = "";
                    break;
            }

            return pReturn;
        }

        public static string TypeToString(byte Type)
        {
            string pResult = null;

            switch (Type)
            {
                case 1:
                    //http://www.freeradius.org/rfc/rfc2865.html#User-Name
                    pResult = "User-Name";
                    break;

                case 2:
                    //http://www.freeradius.org/rfc/rfc2865.html#User-Password
                    pResult = "User-Password";
                    break;

                case 3:
                    //http://www.freeradius.org/rfc/rfc2865.html#CHAP-Password
                    pResult = "CHAP-Password";
                    break;

                case 4:
                    //http://www.freeradius.org/rfc/rfc2865.html#NAS-IP-Address
                    pResult = "NAS-IP-Address";
                    break;

                case 5:
                    //http://www.freeradius.org/rfc/rfc2865.html#NAS-Port
                    pResult = "NAS-Port";
                    break;

                case 6:
                    //http://www.freeradius.org/rfc/rfc2865.html#Service-Type
                    pResult = "Service-Type";
                    break;

                case 8:
                    //http://freeradius.org/rfc/rfc2865.html#Framed-IP-Address
                    pResult = "Framed-IP-Address";
                    break;

                case 11:
                    //http://freeradius.org/rfc/rfc2865.html#Filter-Id
                    pResult = "Filter-Id";
                    break;

                case 20:
                    //http://freeradius.org/rfc/rfc2865.html#Callback-Id
                    pResult = "Callback-Id";
                    break;

                case 31:
                    //http://freeradius.org/rfc/rfc2865.html#Calling-Station-Id
                    pResult = "Calling-Station-Id";
                    break;

                case 32:
                    //http://www.freeradius.org/rfc/rfc2865.html#NAS-Identifier
                    pResult = "NAS-Identifier";
                    break;

                case 87:
                    //http://www.freeradius.org/rfc/rfc2869.html#NAS-Port-Id
                    pResult = "NAS-Port-ID";
                    break;

                default:
                    pResult = "unknown";
                    break;
            }

            return pResult;
        }

    } //internal static partial class Utils
}
