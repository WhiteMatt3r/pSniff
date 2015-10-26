using System;
using System.Net;
using System.Data;
using System.Linq;
using System.Net.Sockets;
using System.Diagnostics;
using System.Windows.Forms;
using System.Net.NetworkInformation;

namespace pSniff
{
    public partial class Form1 : Form
    {
        private bool running = false;
        private Stopwatch timer = new Stopwatch();

        public Form1()
        {
            InitializeComponent();
            timer.Start();
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            comboBox1.Items.Add("All");
            comboBox1.SelectedIndex = 0;
            foreach (NetworkInterface i in interfaces)
            {
                if (i.OperationalStatus == OperationalStatus.Up)
                {
                    try
                    {
                        String ipv4 = i.GetIPProperties().UnicastAddresses[1].Address.ToString();
                        if(!ipv4.Contains(":"))
                        {
                            comboBox1.Items.Add(new mInterface(ipv4,i));
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
            }
            comboBox1.DropDownStyle = ComboBoxStyle.DropDownList;
            int width = listView1.Width / listView1.Columns.Count;
            foreach (ColumnHeader header in listView1.Columns)
            {
                header.Width = width - 5;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {

            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName()).AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork).AsEnumerable();

            String bText = button1.Text;

            if (bText == "Scan: On")
            {
                running = true;
                button1.Text = "Scan: Off";
                if (comboBox1.SelectedIndex == 0)
                {
                    foreach (IPAddress ip in IPv4Addresses)
                        Sniff(ip);
                }
                else
                {
                    Sniff(IPAddress.Parse(((mInterface)comboBox1.SelectedItem).iAddr));
                }
            }
            else
            {
                running = false;
                button1.Text = "Scan: On";
            }

        }

        public static string ToProtocolString(byte b)
        {

            switch (b)
            {
                case 1: return "ICMP";
                case 6: return "TCP";
                case 17: return "UDP";
                default: return "#" + b.ToString();
            }

        }

        public void Sniff(IPAddress ip)
        {

            try
            {
                Socket sck = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                sck.Bind(new IPEndPoint(ip, 0));
                sck.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                sck.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, null);
                byte[] buffer = new byte[24];
                Action<IAsyncResult> OnReceive = null;
                OnReceive = (ar) =>
                {

                    while (timer.ElapsedMilliseconds % 500 != 0) { }

                    String[] row = { new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString(),
                        ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 20))).ToString(),
                        new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString(),
                        ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 22))).ToString() };
                    this.Invoke(new MethodInvoker(delegate ()
                    {
                        listView1.Items.Add(ToProtocolString(buffer.Skip(9).First())).SubItems.AddRange(row);
                        listView1.Items[listView1.Items.Count - 1].EnsureVisible();
                        listView1.Items[listView1.Items.Count - 1].Tag = buffer;
                        label1.Text = "Packets Sniffed: " + listView1.Items.Count;
                    }));
                    buffer = new byte[24];
                    if (running) sck.BeginReceive(buffer, 0, 24, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);

                };
                sck.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None,
                  new AsyncCallback(OnReceive), null);
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message);
            }

        }

        private void button2_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
        }

        private void Form1_Resize(object sender, EventArgs e)
        {
            int width = listView1.Width / listView1.Columns.Count;
            foreach (ColumnHeader header in listView1.Columns)
            {
                header.Width = width - 5;
            }
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            foreach (ListViewItem aRandomName in listView1.SelectedItems)
            {
                String destAddr = aRandomName.SubItems[3].Text;
                byte[] bData = aRandomName.Tag as byte[];
            }
        }
    }
    public class mInterface
    {
        public NetworkInterface iFace;
        public String iAddr;

        public mInterface(String iAddr, NetworkInterface iFace)
        {
            this.iFace = iFace;
            this.iAddr = iAddr;
        }
        public override string ToString()
        {
            return iFace.Name;
        }
    }
}
