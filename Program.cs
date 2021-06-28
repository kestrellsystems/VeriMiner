using McMaster.Extensions.CommandLineUtils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading;

namespace VeriMiner
{
    /// <summary>
    /// adapted from https://github.com/ma261065/DotNetStratumMiner/blob/master/Program.cs
    /// </summary>
    class Program
    {
        private static string Url = "", User = "", Password = "";
        private static int Port;

        private static Miner miner;
        private static Stratum stratum;

        private static float CurrentDifficulty;
        private static Queue<Job> IncomingJobs = new();
        private static BackgroundWorker worker;
        private static int SharesSubmitted = 0;
        private static int SharesAccepted = 0;

        static void Main(string[] args)
        {

            var app = new CommandLineApplication();

            app.HelpOption();
            var url = app.Option("-o|--url <URL>","Pool Domain",CommandOptionType.SingleValue);
            var user = app.Option("-u|--user <name>","Pool username",CommandOptionType.SingleValue);
            var password = app.Option("-p|--password <pass>","Pool password",CommandOptionType.SingleValue);
            var threads = app.Option("-t|--threads <number>", "Number of threads", CommandOptionType.SingleValue);

            app.OnExecute(() =>
            {
                Console.WriteLine("VeriMiner {0}" , typeof(Program).Assembly.GetName().Version);

                //Print intrinsics support
                Utilities.DetermineIntrinsicSupport();

                if (!url.HasValue() || !user.HasValue() || !password.HasValue())
                    Console.Error.WriteLine("you are missing a critical option! -> URL: {0} Username: {1} Password: {2}",url.HasValue(),user.HasValue(),password.HasValue());
                else
                {
                    Url = url.Value().Replace("stratum+", "").Replace("http://", "").Replace("tcp://", "").Split(':')[0].Replace("-o", "").Trim();
                    User = user.Value();
                    Password = password.Value();
                    Port = Convert.ToInt16(url.Value().Split(':')[2]);
                }

                Console.WriteLine("Connecting to {0} on {1}",Url,Port);

                miner = new Miner(Convert.ToInt32(threads.Value()));
                stratum = new Stratum();

                // Set up event handlers
                stratum.GotResponse += Stratum_GotResponse;
                stratum.GotSetDifficulty += Stratum_GotSetDifficulty;
                stratum.GotNotify += Stratum_GotNotify;

                // Connect to the server
                stratum.ConnectToServer(Url, Port, User, Password);

                // Start mining!!
                StartCoinMiner();

                // This thread waits forever as the mining happens on other threads. Can press Ctrl+C to exit
                Thread.Sleep(Timeout.Infinite);

            });

            app.Execute(args);
        } //END Main

        private static void StartCoinMiner()
        {
            // Wait for a new job to appear in the queue
            while (IncomingJobs.Count == 0)
                Thread.Sleep(500);

            // Get the job
            Job ThisJob = IncomingJobs.Dequeue();

            if (ThisJob.CleanJobs)
                stratum.ExtraNonce2 = 0;

            // Increment ExtraNonce2
            stratum.ExtraNonce2++;

            // Calculate MerkleRoot and Target
            string MerkleRoot = Utilities.GenerateMerkleRoot(ThisJob.Coinb1, ThisJob.Coinb2, stratum.ExtraNonce1, stratum.ExtraNonce2.ToString("x8"), ThisJob.MerkleNumbers);
            string Target = Utilities.GenerateTarget(CurrentDifficulty);

            // Update the inputs on this job
            ThisJob.Target = Target;
            ThisJob.Data = ThisJob.Version + ThisJob.PreviousHash + MerkleRoot + ThisJob.NetworkTime + ThisJob.NetworkDifficulty;

            // Start a new miner in the background and pass it the job
            worker = new BackgroundWorker();
            worker.DoWork += new DoWorkEventHandler(miner.Mine);
            worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(CoinMinerCompleted);
            worker.RunWorkerAsync(ThisJob);
        }

        private static void CoinMinerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // If the miner returned a result, submit it
            if (e.Result != null)
            {
                Job ThisJob = (Job)e.Result;
                SharesSubmitted++;

                stratum.SendSUBMIT(ThisJob.JobID, ThisJob.Data.Substring(68 * 2, 8), ThisJob.Answer.ToString("x8"), CurrentDifficulty);
            }

            // Mine again
            StartCoinMiner();
        }

        private static void Stratum_GotResponse(object sender, StratumEventArgs e)
        {
            StratumResponse Response = (StratumResponse)e.MiningEventArg;

            Console.Write("Got Response to {0} - ", (string)sender);

            switch ((string)sender)
            {
                case "mining.authorize":
                    if ((bool)Response.result)
                        Console.WriteLine("Worker authorized");
                    else
                    {
                        Console.WriteLine("Worker rejected");
                        Environment.Exit(-1);
                    }
                    break;

                case "mining.subscribe":
                    stratum.ExtraNonce1 = (string)((object[])Response.result)[1];
                    Console.WriteLine("Subscribed. ExtraNonce1 set to " + stratum.ExtraNonce1);
                    break;

                case "mining.submit":
                    if (Response.result != null && (bool)Response.result)
                    {
                        SharesAccepted++;
                        Console.WriteLine("Share accepted ({0} of {1})", SharesAccepted, SharesSubmitted);
                    }
                    else
                        Console.WriteLine("Share rejected. {0}", Response.error[1]);
                    break;
            }
        }

        private static void Stratum_GotSetDifficulty(object sender, StratumEventArgs e)
        {
            StratumCommand Command = (StratumCommand)e.MiningEventArg;
            CurrentDifficulty = Convert.ToSingle(Command.parameters[0]);

            Console.WriteLine("Got Set_Difficulty: {0}", CurrentDifficulty);
        }

        private static void Stratum_GotNotify(object sender, StratumEventArgs e)
        {
            Job ThisJob = new();
            StratumCommand Command = (StratumCommand)e.MiningEventArg;

            ThisJob.JobID = (string)Command.parameters[0];
            ThisJob.PreviousHash = (string)Command.parameters[1];
            ThisJob.Coinb1 = (string)Command.parameters[2];
            ThisJob.Coinb2 = (string)Command.parameters[3];
            Array a = (Array)Command.parameters[4];
            ThisJob.Version = (string)Command.parameters[5];
            ThisJob.NetworkDifficulty = (string)Command.parameters[6];
            ThisJob.NetworkTime = (string)Command.parameters[7];
            ThisJob.CleanJobs = (bool)Command.parameters[8];

            ThisJob.MerkleNumbers = new string[a.Length];

            int i = 0;
            foreach (string s in a)
                ThisJob.MerkleNumbers[i++] = s;

            // Cancel the existing mining threads and clear the queue if CleanJobs = true
            if (ThisJob.CleanJobs)
            {
                Console.WriteLine("Stratum detected a new block. Stopping old threads.");

                IncomingJobs.Clear();
                miner.done = true;
            }

            // Add the new job to the queue
            IncomingJobs.Enqueue(ThisJob);
        }

        public class Job
        {
            // Inputs
            public string JobID;
            public string PreviousHash;
            public string Coinb1;
            public string Coinb2;
            public string[] MerkleNumbers;
            public string Version;
            public string NetworkDifficulty;
            public string NetworkTime;
            public bool CleanJobs;

            // Intermediate
            public string Target;
            public string Data;

            // Output
            public uint Answer;
        }
    }
}
