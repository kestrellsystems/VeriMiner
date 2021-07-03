using System;
using System.Collections;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Text;

namespace VeriMiner
{
    /// <summary>
    /// adapted from: https://github.com/ma261065/DotNetStratumMiner/blob/master/Stratum.cs
    /// </summary>
    class Stratum
    {
        public event EventHandler<StratumEventArgs> GotSetDifficulty;
        public event EventHandler<StratumEventArgs> GotNotify;
        public event EventHandler<StratumEventArgs> GotResponse;

        public static Hashtable PendingACKs = new();
        public TcpClient tcpClient;
        private int SharesSubmitted = 0;
        private string page = "";
        public string ExtraNonce1 = "";
        public int ExtraNonce2 = 0;
        private string Server;
        private int Port;
        private string Username;
        private string Password;
        public int ID;

        public void ConnectToServer(string MineServer, int MinePort, string MineUser, string MinePassword)
        {
            try
            {
                ID = 1;
                Server = MineServer;
                Port = MinePort;
                Username = MineUser;
                Password = MinePassword;
                tcpClient = new TcpClient(AddressFamily.InterNetwork);

                // Start an asynchronous connection
                tcpClient.BeginConnect(Server, Port, new AsyncCallback(ConnectCallback), tcpClient);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
            }
        }

        private void ConnectCallback(IAsyncResult result)
        {
            if (tcpClient.Connected)
                Console.WriteLine("Connected");
            else
            {
                Console.WriteLine("Unable to connect to server {0} on port {1}", Server, Port);
                Environment.Exit(-1);
            }

            // We are connected successfully
            try
            {
                SendSUBSCRIBE();
                SendAUTHORIZE();

                NetworkStream networkStream = tcpClient.GetStream();
                byte[] buffer = new byte[tcpClient.ReceiveBufferSize];

                // Now we are connected start async read operation.
                networkStream.BeginRead(buffer, 0, buffer.Length, ReadCallback, buffer);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
            }
        }

        public void SendSUBSCRIBE()
        {
            StratumCommand Command = new()
            {
                id = ID++,
                method = "mining.subscribe",
                parameters = new ArrayList()
            };

            byte[] bytesSent = Encoding.ASCII.GetBytes(Utilities.JsonSerialize(Command) + "\n");

            try
            {
                tcpClient.GetStream().Write(bytesSent, 0, bytesSent.Length);
                PendingACKs.Add(Command.id, Command.method);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
                ConnectToServer(Server, Port, Username, Password);
            }
        }

        public void SendAUTHORIZE()
        {
            StratumCommand Command = new()
            {
                id = ID++,
                method = "mining.authorize",
                parameters = new ArrayList
                {
                    Username,
                    Password
                }
            };

            byte[] bytesSent = Encoding.ASCII.GetBytes(Utilities.JsonSerialize(Command) + "\n");

            try
            {
                tcpClient.GetStream().Write(bytesSent, 0, bytesSent.Length);
                PendingACKs.Add(Command.id, Command.method);
            }
            catch(Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
                ConnectToServer(Server, Port, Username, Password);
            }
        }

        public void SendSUBMIT(string JobID, string nTime, string Nonce, double Difficulty)
        {
            StratumCommand Command = new()
            {
                id = ID++,
                method = "mining.submit",
                parameters = new ArrayList
            {
                Username,
                JobID,
                ExtraNonce2.ToString("x8"),
                nTime,
                Nonce
            }
            };

            byte[] bytesSent = Encoding.ASCII.GetBytes(Utilities.JsonSerialize(Command) + "\n");

            try
            {
                tcpClient.GetStream().Write(bytesSent, 0, bytesSent.Length);
                PendingACKs.Add(Command.id, Command.method);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
                ConnectToServer(Server, Port, Username, Password);
            }

            SharesSubmitted++;
            Console.WriteLine("{0} - Submit (Difficulty {1})", DateTime.Now, Difficulty);
        }

        // Callback for Read operation
        private void ReadCallback(IAsyncResult result)
        {
            NetworkStream networkStream;
            int bytesread;
            
            byte[] buffer = result.AsyncState as byte[];
            
            try
            {
                networkStream = tcpClient.GetStream();
                bytesread = networkStream.EndRead(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socket error:" + ex.Message);
                return;
            }

            if (bytesread == 0)
            {
                Console.WriteLine(DateTime.Now +  " Disconnected. Reconnecting...");
                tcpClient.Close();
                tcpClient = null;
                PendingACKs.Clear();
                ConnectToServer(Server, Port, Username, Password);
                return;
            }

            // Get the data
            string data = Encoding.ASCII.GetString(buffer, 0, bytesread);

            page += data;

            int FoundClose = page.IndexOf('}');

            while (FoundClose > 0)
            {
                string CurrentString = page.Substring(0, FoundClose + 1);

                // We can get either a command or response from the server. Try to deserialise both
                StratumCommand Command = Utilities.JsonDeserialize<StratumCommand>(CurrentString);
                StratumResponse Response = Utilities.JsonDeserialize<StratumResponse>(CurrentString);

                StratumEventArgs e = new();

                if (Command.method != null)             // We got a command
                {
                    e.MiningEventArg = Command;

                    switch (Command.method)
                    {
                        case "mining.notify":
                            GotNotify?.Invoke(this, e);
                            break;
                        case "mining.set_difficulty":
                            GotSetDifficulty?.Invoke(this, e);
                            break;
                    }
                }
                else if (Response.error != null || Response.result != null)       // We got a response
                {
                    e.MiningEventArg = Response;

                    // Find the command that this is the response to and remove it from the list of commands that we're waiting on a response to
                    string Cmd = (string)PendingACKs[Response.id];
                    PendingACKs.Remove(Response.id);

                    if (Cmd == null)
                        Console.WriteLine("Unexpected Response");
                    else GotResponse?.Invoke(Cmd, e);
                }

                page = page.Remove(0, FoundClose + 2);
                FoundClose = page.IndexOf('}');
            }

            // Then start reading from the network again.
            networkStream.BeginRead(buffer, 0, buffer.Length, ReadCallback, buffer);
        }
    }

    [DataContract]
    public class StratumCommand
    {
        [DataMember]
        public string method;
        [DataMember]
        public int? id;
        [DataMember(Name = "params")]
        public ArrayList parameters;
    }

    [DataContract]
    public class StratumResponse
    {
        [DataMember]
        public ArrayList error;
        [DataMember]
        public int? id;
        [DataMember]
        public object result;
    }

    public class StratumEventArgs:EventArgs
    {
        public object MiningEventArg;
    }
}
