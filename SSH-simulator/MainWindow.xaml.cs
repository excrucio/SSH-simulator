using Microsoft.Win32;
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
        internal int step = 0;

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

            //****************
            // koraci
            //****************

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
            steps.Add(() => { /* ništa */ });

            //6
            steps.Add(() => server.SetAlgorithms());
            steps.Add(() => ShowAlgorithms());

            //7
            steps.Add(() => { tab_dh.Focus(); });
            steps.Add(() => client.CalculateDH());

            //8
            steps.Add(() => server.CalculateDH());
            steps.Add(() => {/* ništa */ });

            //9
            steps.Add(() => client.SendDHPacket());
            steps.Add(() => server.ReadDHPacket());

            //10
            steps.Add(() => server.SendDHPacket());
            steps.Add(() => client.ReadDHPacket());

            //11
            steps.Add(() => { tab_keys.Focus(); });
            steps.Add(() => { /* ništa */ });

            //12
            steps.Add(() => client.GenerateEncryptionKeys());
            steps.Add(() => { /* ništa */ });

            //13
            steps.Add(() => server.GenerateEncryptionKeys());
            steps.Add(() => { /* ništa */ });

            //14
            steps.Add(() => client.SendNEWKEYSPacket());
            steps.Add(() => server.ReadNEWKEYSPacket());

            //15
            steps.Add(() => server.SendNEWKEYSPacket());
            steps.Add(() => client.ReadNEWKEYSPacket());

            //16
            steps.Add(() => { tab_auth.Focus(); });
            steps.Add(() => { ShowDialogMsg("Sav promet od sada je enkrpitiran!"); });

            //17
            steps.Add(() => client.SendServiceRequestPacket());
            steps.Add(() => server.ReadServiceRequestPacket());

            //18
            steps.Add(() => server.SendServiceAcceptPacket());
            steps.Add(() => client.ReadServiceAcceptPacket());

            //19
            steps.Add(() => client.SendAuth());
            steps.Add(() => server.ReadAuth());

            //20
            steps.Add(() => server.SendAuthResponse());
            steps.Add(() => client.ReadAuthResponse());

            //21
            steps.Add(() => { tab_protokol.Focus(); });
            steps.Add(() => { /* ništa */ });

            //22
            steps.Add(() => client.SendChannelOpenPacket());
            steps.Add(() => server.ReadChannelOpenPacket());

            //23
            steps.Add(() => server.SendChannelOpenResponse());
            steps.Add(() => client.ReadChannelOpenResponse());

            //24
            steps.Add(() => client.SendChannelRequestPacket());
            steps.Add(() => server.ReadChannelRequestPacket());

            //25
            steps.Add(() =>
            {
                server.SendChannelRespondPacket();
                client.ReadChannelResponsePacket();
            });
            steps.Add(() => ServerCommandExecutingAndSendingData());
        }

        private void ServerCommandExecutingAndSendingData()
        {
            try
            {
                string data = server.ExecuteCommand();
                bool more = false;
                do
                {
                    more = server.SendChannelDataPackets(data);
                    if (more)
                    {
                        client.ReadChannelDataPacket();
                    }
                } while (more);

                client.ShowDataReceived();
            }
            catch
            {
                retResult = "Paket nije moguće prenijeti!";
                step -= 3;
                return;
            }

            boolRetResult = true;
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
            button_next.IsEnabled = false;

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
                    button_next.IsEnabled = false;
                    ShowDialogMsg(retResult);

                    break;
                }
            }

            // odskrolaj sve
            textBox_info.ScrollToEnd();
            textBox_client.ScrollToEnd();
            textBox_client_decoded.ScrollToEnd();
            textBox_server.ScrollToEnd();
            textBox_server_decoded.ScrollToEnd();

            if (boolRetResult == false)
            {
                return;
            }

            button_next.IsEnabled = true;
        }

        public void ShowDialogMsg(string retResult)
        {
            MessageBox.Show(retResult);
        }

        private void button_reset_Click(object sender, RoutedEventArgs e)
        {
            var win = App.Current.MainWindow;
            App.Current.MainWindow = new MainWindow();

            win.Close();
            App.Current.MainWindow.Show();

            return;

            // resetiraj sve korake
            InitializeSteps();

            // glavno
            textBox_client.Text = "";
            textBox_client_decoded.Text = "";
            textBox_info.Text = "";
            textBox_server.Text = "";
            textBox_server_decoded.Text = "";
            button_next.IsEnabled = true;
            tab_algoritmi.Focus();

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
            checkBox_server_ssh_rsa.IsChecked = true;
            checkBox_ssh_rsa.IsChecked = true;

            // drugi tab
            textBox_cli_mod_p.Text = "";
            textBox_cli_g.Text = "";
            textBox_cli_H.Text = "";
            textBox_cli_K.Text = "";
            textBox_e.Text = "";
            textBox_f.Text = "";
            textBox_x.Text = "";
            textBox_y.Text = "";
            textBox_ser_pub_key.Text = "";
            textBox_sig_ser.Text = "";
            textBox_ser_g.Text = "";
            textBox_ser_H.Text = "";
            textBox_ser_K.Text = "";
            textBox_ser_mod_p.Text = "";

            // treći tab
        }

        private void button_baza_korisnika_Click(object sender, RoutedEventArgs e)
        {
            // Create an instance of the open file dialog box.
            OpenFileDialog openFileDialog1 = new OpenFileDialog();

            // Set filter options and filter index.
            openFileDialog1.Filter = "Text Files (.txt)|*.txt|All Files (*.*)|*.*";
            openFileDialog1.FilterIndex = 1;

            openFileDialog1.Multiselect = false;

            // Call the ShowDialog method to show the dialog box.
            bool? userClickedOK = openFileDialog1.ShowDialog();

            // Process input if the user clicked OK.
            if (userClickedOK == true)
            {
                textBox_baza_korisnika.Text = openFileDialog1.FileName;
            }
        }
    }
}