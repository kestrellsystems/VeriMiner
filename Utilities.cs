using System;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace VeriMiner
{
    /// <summary>
    /// adapted from: https://github.com/ma261065/DotNetStratumMiner/blob/master/Utilities.cs
    /// </summary>
    public static class Utilities
    {
        public static byte[] HexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException(string.Format("The binary key cannot have an odd number of digits: {0}", hexString));
            }

            byte[] HexAsBytes = new byte[hexString.Length / 2];

            for (int index = 0; index < HexAsBytes.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                HexAsBytes[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return HexAsBytes;
        }

        public static string ByteArrayToHexString(byte[] byteArray)
        {
            string result = "";

            foreach (byte b in byteArray)
                result += string.Format("{0:x2}", b);

            return result;
        }

        public static byte[] ReverseByteArrayByFours(byte[] byteArray)
        {
            byte temp;

            if (byteArray.Length % 4 != 0)
            {
                throw new ArgumentException(string.Format("The byte array length must be a multiple of 4"));
            }

            for (int index = 0; index < byteArray.Length; index += 4)
            {
                temp = byteArray[index];
                byteArray[index] = byteArray[index + 3];
                byteArray[index + 3] = byteArray[index + 2];
                byteArray[index + 2] = byteArray[index + 1];
                byteArray[index + 1] = byteArray[index + 3];
                byteArray[index + 3] = temp;
            }

            return byteArray;
        }
        
        public static string GenerateMerkleRoot(string Coinb1, string Coinb2, string ExtraNonce1, string ExtraNonce2, string[] MerkleNumbers)
        {
            string Coinbase = Coinb1 + ExtraNonce1 + ExtraNonce2 + Coinb2;

            byte[] Coinbasebytes = HexStringToByteArray(Coinbase);

            SHA256 mySHA256 = SHA256.Create();
            mySHA256.Initialize();
            byte[] hashValue;

            // Create Coinbase hash by DoubleSHA of Coinbase
            hashValue = mySHA256.ComputeHash(mySHA256.ComputeHash(Coinbasebytes));

            // Calculate Merkle Root by double-hashing the Coinbase hash with each Merkle number in turn
            foreach (string s in MerkleNumbers)
            {
                hashValue = mySHA256.ComputeHash(mySHA256.ComputeHash(HexStringToByteArray(ByteArrayToHexString(hashValue) + s)));
            }
            
            return ByteArrayToHexString(ReverseByteArrayByFours(hashValue));
        }

        public static byte[] GenerateTarget(double Difficulty)
        {
            // Calculate Target (which is the reverse of 0x 0000ffff 00000000 00000000 00000000 00000000 00000000 00000000 00000000 / difficulty
            byte[] ba = { 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            int index = 0;
            double d = Difficulty;
            int n = ba[0];
            byte[] result = new byte[32];

            do
            {
                int r = (int)(n / d);
                result[index] = (byte)r;
                int x = (int)(n - r * d);

                if (++index == ba.Length)
                    break;

                n = (x << 8) + ba[index];
            }
            while (true);

            return result;
        }

        /// <summary>        
        /// Deserializes an object from a UTF-8 encoded JSON string.        
        /// </summary>        
        /// <typeparam name="T">type of object to deserialize as</typeparam>        
        /// <param name="json">UTF-8 encoded JSON string</param>        
        /// <returns>deserialized object</returns>        
        public static T JsonDeserialize<T>(string json)
        {
            // Load json into memorystream and deserialize            
            MemoryStream ms = new(Encoding.UTF8.GetBytes(json));

            DataContractJsonSerializer s = new(typeof(T));
            T result = (T)s.ReadObject(ms);
            ms.Close();
            return result;
        }
    }
}

