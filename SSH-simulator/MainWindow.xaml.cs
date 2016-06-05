using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SSH_simulator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public string retResult;
        public bool boolRetResult;

        private Client client;
        private Server server;

        private List<Action> steps = new List<Action>();
        private int step = 0;

        public MainWindow()
        {
            InitializeComponent();

            InitializeSteps();
        }

        private void InitializeSteps()
        {
            var ms = new MemoryStream();
            client = new Client(ms, this);
            server = new Server(ms, this);

            steps = new List<Action>();
            step = 0;
            retResult = "";
            boolRetResult = false;

            //1
            steps.Add(() => client.SendIdentifierToServer());
            steps.Add(() => server.ReadClientId());

            //2
            steps.Add(() => server.SendIdentifierToClient());
            steps.Add(() => client.ReadServerId());

            //3
            steps.Add(() => client.SendKEXINIT());
            steps.Add(() => server.ReadKEXINIT());

            //4
            steps.Add(() => server.SendKEXINIT());
            steps.Add(() => client.ReadKEXINIT());

            //5
            steps.Add(() => client.SetAlgorithms());
            steps.Add(() => server.SetAlgorithms());

            //6
            steps.Add(() => ShowAlgorithms());
            steps.Add(() => {/* ništa*/ });
        }

        private void ShowAlgorithms()
        {
            var algs = client.GetAlgorithmsToUse();

            MessageBox.Show("Razmjena ključeva:\t" + algs.DH_algorithm
                            + "\nDigitalni potpis:\t" + algs.SIGNATURE_algorithm
                            + "\nEnkripcija:\t\t" + algs.ENCRYPTION_algorithm
                            + "\nMAC:\t\t" + algs.MAC_algorithm
                            + "\nKompresija:\tnone"
                            , "Dogovoreni algortimi");

            tab_dh.Focus();
        }

        private void button_next_Click(object sender, RoutedEventArgs e)
        {
            for (int i = 0; i < 2; i++)
            {
                if (steps.Count <= step)
                {
                    // TODO provjeriti
                    step -= 4;
                    if (step < 0)
                    {
                        step = 0;
                    }
                }

                steps[step].Invoke();
                step++;

                if (boolRetResult == false)
                {
                    ShowDialogMsg(retResult);
                    button_next.IsEnabled = false;
                }
            }

            // odskrolaj sve
            textBox_info.ScrollToEnd();
            textBox_client.ScrollToEnd();
            textBox_client_decoded.ScrollToEnd();
            textBox_server.ScrollToEnd();
            textBox_server_decoded.ScrollToEnd();
        }

        private void ShowDialogMsg(string retResult)
        {
            MessageBox.Show(retResult);
        }

        private void button_reset_Click(object sender, RoutedEventArgs e)
        {
            // resetiraj sve korake
            InitializeSteps();

            // glavno
            textBox_client.Text = "";
            textBox_client_decoded.Text = "";
            textBox_info.Text = "";
            textBox_server.Text = "";
            textBox_server_decoded.Text = "";
            button_next.IsEnabled = true;

            //prvi tab
            textBox_serverIdent.Text = "SSH-2.0-server_v1.0";
            textBox_clientIdent.Text = "SSH-2.0-client_v1.0";
            checkBox_aes256_cbc.IsChecked = false;
            checkBox_blowfish_ctr.IsChecked = false;
            checkBox_ec_dh.IsChecked = false;
            checkBox_gost28147.IsChecked = false;
            checkBox_hmac_sha2.IsChecked = false;
            checkBox_server_aes256_cbc.IsChecked = false;
            checkBox_server_blowfish_ctr.IsChecked = false;
            checkBox_server_ec_dh.IsChecked = false;
            checkBox_server_gost28147.IsChecked = false;
            checkBox_server_hmac_sha2.IsChecked = false;
            checkBox_server_ssh_rsa.IsChecked = false;
            checkBox_ssh_rsa.IsChecked = false;

            // drugi tab
            // TODO drugi tab reset
        }
    }
}