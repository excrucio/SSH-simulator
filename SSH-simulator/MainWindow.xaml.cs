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

            steps.Add(() => client.SendIdentifierToServer());
            steps.Add(() => server.ReadClientId());
            steps.Add(() => server.SendIdentifierToClient());
            steps.Add(() => client.ReadServerId());
            steps.Add(() => client.SendKEXINIT());
            steps.Add(() => server.ReadKEXINIT());
        }

        private void button_next_Click(object sender, RoutedEventArgs e)
        {
            for (int i = 0; i <= 1; i++)
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
                    ShowError(retResult);
                }
            }
        }

        private void ShowError(string retResult)
        {
            //TODO da pokaže error nekakav
        }
    }
}