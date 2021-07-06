using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace VeriMiner
{
    /// <summary>
    /// adapted from: https://github.com/ma261065/DotNetStratumMiner/blob/master/Miner.cs
    /// </summary>
    class Miner
    {
        // General Variables
        public volatile bool done = false;
        public volatile uint FinalNonce = 0;
           
        Task[] MineTasks;

        public Miner(int? optThreadCount = null)
        {
            int threadCount = optThreadCount ?? Environment.ProcessorCount;
            if (threadCount > Environment.ProcessorCount) {
                threadCount = Environment.ProcessorCount;
            }
            MineTasks = new Task[threadCount];
        }
       
        public void Mine(object sender, DoWorkEventArgs e)
        {
            Console.WriteLine("Starting {0} Tasks for new block...", MineTasks.Length);

            Program.Job ThisJob = (Program.Job)e.Argument;
            
            // Gets the data to hash and the target from the work
            byte[] databyte = Utilities.ReverseByteArrayByFours(Utilities.HexStringToByteArray(ThisJob.Data));
            byte[] targetbyte = ThisJob.Target;
            
            done = false;
            FinalNonce = 0;

            // Spin up background threads to do the hashing
            for (int i = 0; i < MineTasks.Length; i++)
            {
                MineTasks[i] = new(() => DoScrypt(databyte, targetbyte, (uint)i, (uint)MineTasks.Length));
                MineTasks[i].Start();
            }

            // Block until all the threads finish
            Task.WaitAll(MineTasks);
           
            // Fill in the answer if work done
            if (FinalNonce != 0)
            {
                ThisJob.Answer = FinalNonce;
                e.Result = ThisJob;
            }
            else
                e.Result = null;
        }

        // Reference: https://github.com/replicon/Replicon.Cryptography.SCrypt
        public void DoScrypt(byte[] Tempdata, byte[] Target, uint Nonce, uint Increment)
        {
            double Hashcount = 0;

            byte[] Databyte = new byte[80];

            Array.Copy(Tempdata, 0, Databyte, 0, 76);
            
            DateTime StartTime = DateTime.Now;
            
            try
            {
                byte[] ScryptResult = new byte[32];

                // Loop until done is set or we meet the target
                while (!done)
                {
                    ScryptResult = Scrypt_Intrinsic.Hash(Databyte, Nonce);

                    Hashcount++;
                    Console.WriteLine("Target: {0} \n Hash: {1}", Utilities.ByteArrayToHexString(Target), Utilities.ByteArrayToHexString(ScryptResult));

                    for (int i = ScryptResult.Length - 1; i >= 0; i--) //Did we meet the target?
                    {
                        if ((ScryptResult[i] & 0xff) > (Target[i] & 0xff))
                            break;
                        if ((ScryptResult[i] & 0xff) < (Target[i] & 0xff))
                        {
                            FinalNonce = Nonce;
                            done = true;
                            break;
                        }
                    }

                    Nonce += Increment; // If not, increment the nonce and try again
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                FinalNonce = 0;
            }

            double Elapsedtime = (DateTime.Now - StartTime).TotalSeconds;
            Console.WriteLine("Thread finished - {0:0} hashes in {1:0.00} s. Speed: {2:0.00} Hash/s", Hashcount, Elapsedtime, Hashcount / Elapsedtime);
        }
    }

}
