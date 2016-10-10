using System;
using System.Windows;
using System.Windows.Input;
using Gurock.SmartInspect;
using System.Text.RegularExpressions;

namespace TestRadius
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        Logging lg;
        public MainWindow()
        {
            InitializeComponent();
             lg = new Logging();

        }

        private void btnTest_Click(object sender, RoutedEventArgs e)
        {
            SiAuto.Main.LogVerbose("Testing Radius");
            try
            {

                if ((tbRIP.Text != null & tbRIP.Text != "") & (tbSS.Password != null & tbSS.Password != "") & (tbUN.Text != null & tbUN.Text != "") & (tbPW.Password != null & tbPW.Password != ""))
                {
                    testRadius tRadius = new testRadius();
                    if(tbPrt.Text == "" | tbPrt.Text == null)
                    {
                        tbPrt.Text = "1812";
                    }
                    tRadius.GetStatus(tbRIP.Text, Convert.ToInt32(tbPrt.Text), tbSS.Password, tbUN.Text, tbPW.Password);

                    switch (tRadius.RadiusStatus)
                    {
                        case 0:
                            {
                                tbResults.Text = "Access Accepted";
                            }
                            break;
                        case -4:
                            {
                                tbResults.Text = "Access Rejected";
                            }
                            break;
                        case -8:
                            {
                                tbResults.Text = "Access Challenged";
                            }
                            break;
                        default:
                            {
                                tbResults.Text = string.Format("Error {1}: {0}", tRadius.RadiusMessage, tRadius.RadiusStatus);
                            }
                            break;
                    }
                }
                else
                {
                    tbResults.Text = "Please complete filling out the text boxes";
                }
            }
            catch(Exception ex)
            {
                SiAuto.Main.LogError("Application Error: {0}", ex.Message);
            }
        }

        private void NumberValidationTextBox(object sender, TextCompositionEventArgs e)
        {
            Regex regex = new Regex("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }
    }
}
