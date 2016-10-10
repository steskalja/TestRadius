using System;
using System.Threading;
using System.Net.nRadius;
using System.Net.NetworkInformation;
using System.Text;
using Gurock.SmartInspect;

namespace TestRadius
{
    public class testRadius
    {
        string RS;
        string SS;
        string UN;
        string PW;
        string tRadiusMessage = null;

        delegate int rtResult();
        public testRadius(string rs = "", string ss = "", string un= "", string pw = "")
        {
            RS = rs;
            SS = ss;
            UN = un;
            PW = pw;
        }
        public int RadiusStatus
        {
            get
            {
                return rStatus;
            }
        }
        public string RadiusMessage
        {
            get
            {
                return tRadiusMessage;
            }
        }
        private int rStatus = -2;
        public void GetStatus(string RadiusServer = "", int port = 1812, string SharedSecret = "",string UserName = "", string Password = "")
        {
            SiAuto.Main.LogVerbose("Getting Radius Status for Server {0} on port {1}", RadiusServer, port);
            if (RadiusServer == "")
            {
                RadiusServer = RS;
            }
            if (SharedSecret == "")
            {
                SharedSecret = SS;
            }
            if (UserName == "")
            {
                UserName = UN;
            }
            if (Password == "")
            {
                Password = PW;
            }
            try
            {
                if(PingHost(RadiusServer))
                { 
                    nRadius_Client nrClient = new nRadius_Client(RadiusServer, SharedSecret, UserName, Password);
                    nrClient.Port = port;
                    rtResult GetrtResult = new rtResult(nrClient.Authenticate);
                    IAsyncResult result = GetrtResult.BeginInvoke(null,null);
                    while(result.IsCompleted != true)
                    {
                        Thread.Sleep(100);
                    }
                    rStatus = GetrtResult.EndInvoke(result);
                    tRadiusMessage = nrClient.Response;
                    SiAuto.Main.LogVerbose("Authentication Status for Radius Server {0}: {1}, {2}", RadiusServer, rStatus, tRadiusMessage);
                }
            }
            catch (Exception ex)
            {
                SiAuto.Main.LogError(ex.Message);
            }
        }

        bool PingHost(string host)
        {

            Ping pingSender = new Ping();
            PingOptions options = new PingOptions();

            // Use the default Ttl value which is 128,
            // but change the fragmentation behavior.
            options.DontFragment = true;

            // Create a buffer of 32 bytes of data to be transmitted.
            string data = String.Format("This is a Test of host {0}",host);

            if(data.Length > 32)
            {
                data = data.Substring(0, 32);
            }
            SiAuto.Main.LogDebug("Ping test buffer for {0}: {1}", host, data);
            byte[] buffer = Encoding.ASCII.GetBytes(data);
            int timeout = 120;
            PingReply reply = pingSender.Send(host, timeout, buffer, options);
            if (reply.Status == IPStatus.Success)
            {
                return true;
            }
            else
            {
                throw new Exception(reply.Status.ToString());
            }
        }


    }
}
