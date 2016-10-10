using System;
using Gurock.SmartInspect;

namespace TestRadius
{
    class Logging
    {
        public Logging()
        {

            string exepath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string aName = System.Reflection.Assembly.GetExecutingAssembly().FullName.Split(',')[0];
            string logfile = @"\TestRadius.log";
            string logpath = exepath.Substring(0, exepath.LastIndexOf(@"\"));
            logpath = logpath + logfile;
            string aVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(exepath).FileVersion;
            SiAuto.Si.Error += new Gurock.SmartInspect.ErrorEventHandler(Si_Error);
            SiAuto.Si.SetVariable("logfile", logpath);
            SiAuto.Si.LoadConfiguration(exepath.Substring(0, exepath.LastIndexOf(@"\")) + @"\Settings\TestRadius.sic");
            SiAuto.Main.LogMessage("*******************************************************");
            SiAuto.Main.LogMessage("{0} Computer Name: {1} Version: {2}", aName, Environment.MachineName, aVersion);
            SiAuto.Main.LogMessage("*******************************************************");
        }

        private void Si_Error(object sender, Gurock.SmartInspect.ErrorEventArgs e)
        {
            Console.WriteLine(e.Exception);

            if (e.Exception is LoadConfigurationException)
            {
                LoadConfigurationException le = (LoadConfigurationException)e.Exception;
                Console.WriteLine(le.FileName);
            }

        }

    }
}