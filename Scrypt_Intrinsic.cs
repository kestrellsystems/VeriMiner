using System;
using System.Numerics;
using System.Security.Cryptography;

namespace VeriMiner
{
    public static class Scrypt_Intrinsic
    {
        private static HMACSHA256 hmac;
        private static byte[] H = new byte[32];
        private static byte[] B = new byte[128+4];
        private static uint[] X = new uint[32];
        private static uint[] V = new uint[32 * 1048576];

        /// <summary>
        /// Scrypt hash cycle
        /// </summary>
        /// <param name="header">block header </param>
        /// <param name="nonce">nonce </param>
        /// <returns>Blocker header hashed with nonce </returns>
        public static byte[] Hash(byte[] header, uint nonce)
        {
            uint i, j, k;

            Array.Copy(header, 0, B, 0, 76);
            B[76] = (byte)(nonce >> 0);
            B[77] = (byte)(nonce >> 8);
            B[78] = (byte)(nonce >> 16);
            B[79] = (byte)(nonce >> 24);

            hmac = new HMACSHA256(B);

            B[80] = 0;
            B[81] = 0;
            B[82] = 0;

            for (i = 0; i < 4; i++)
            {
                B[83] = (byte)(i + 1);
                H = hmac.ComputeHash(B, 0, 84);

                for (j = 0; j < 8; j++)
                {
                    X[i * 8 + j] = (uint)((H[j * 4 + 0] & 0xff) << 0
                                  | (H[j * 4 + 1] & 0xff) << 8
                                  | (H[j * 4 + 2] & 0xff) << 16
                                  | (H[j * 4 + 3] & 0xff) << 24);
                }
            }

            //update with scrypt-N value
            for (i = 0; i < 1048576; i++)
            {
                Array.Copy(X, 0, V, i * 32, 32);

                XorSalsa8(0, 16);
                XorSalsa8(16, 0);
            }
            //update with scrypt-N value
            for (i = 0; i < 1048576; i++)
            {
                k = (X[16] & 1048575) * 32;

                for (j = 0; j < 32; j++)
                    X[j] ^= V[k + j];

                XorSalsa8(0, 16);
                XorSalsa8(16, 0);
            }

            //Little endian?
            for (i = 0; i < 32; i++)
            {
                B[i * 4 + 0] = (byte)(X[i] >> 0);
                B[i * 4 + 1] = (byte)(X[i] >> 8);
                B[i * 4 + 2] = (byte)(X[i] >> 16);
                B[i * 4 + 3] = (byte)(X[i] >> 24);
            }

            B[128 + 3] = 1;
            H = hmac.ComputeHash(B, 0, 128 + 4);

            return H;

        } // End Hash

        private static void XorSalsa8(int di, int xi)
        {
            uint x00 = X[di + 0] ^= X[xi + 0];
            uint x01 = X[di + 1] ^= X[xi + 1];
            uint x02 = X[di + 2] ^= X[xi + 2];
            uint x03 = X[di + 3] ^= X[xi + 3];
            uint x04 = X[di + 4] ^= X[xi + 4];
            uint x05 = X[di + 5] ^= X[xi + 5];
            uint x06 = X[di + 6] ^= X[xi + 6];
            uint x07 = X[di + 7] ^= X[xi + 7];
            uint x08 = X[di + 8] ^= X[xi + 8];
            uint x09 = X[di + 9] ^= X[xi + 9];
            uint x10 = X[di + 10] ^= X[xi + 10];
            uint x11 = X[di + 11] ^= X[xi + 11];
            uint x12 = X[di + 12] ^= X[xi + 12];
            uint x13 = X[di + 13] ^= X[xi + 13];
            uint x14 = X[di + 14] ^= X[xi + 14];
            uint x15 = X[di + 15] ^= X[xi + 15];
            for (int i = 0; i < 8; i += 2)
            {
                x04 ^= BitOperations.RotateLeft(x00 + x12, 7); x08 ^= BitOperations.RotateLeft(x04 + x00, 9);
                x12 ^= BitOperations.RotateLeft(x08 + x04, 13); x00 ^= BitOperations.RotateLeft(x12 + x08, 18);
                x09 ^= BitOperations.RotateLeft(x05 + x01, 7); x13 ^= BitOperations.RotateLeft(x09 + x05, 9);
                x01 ^= BitOperations.RotateLeft(x13 + x09, 13); x05 ^= BitOperations.RotateLeft(x01 + x13, 18);
                x14 ^= BitOperations.RotateLeft(x10 + x06, 7); x02 ^= BitOperations.RotateLeft(x14 + x10, 9);
                x06 ^= BitOperations.RotateLeft(x02 + x14, 13); x10 ^= BitOperations.RotateLeft(x06 + x02, 18);
                x03 ^= BitOperations.RotateLeft(x15 + x11, 7); x07 ^= BitOperations.RotateLeft(x03 + x15, 9);
                x11 ^= BitOperations.RotateLeft(x07 + x03, 13); x15 ^= BitOperations.RotateLeft(x11 + x07, 18);
                x01 ^= BitOperations.RotateLeft(x00 + x03, 7); x02 ^= BitOperations.RotateLeft(x01 + x00, 9);
                x03 ^= BitOperations.RotateLeft(x02 + x01, 13); x00 ^= BitOperations.RotateLeft(x03 + x02, 18);
                x06 ^= BitOperations.RotateLeft(x05 + x04, 7); x07 ^= BitOperations.RotateLeft(x06 + x05, 9);
                x04 ^= BitOperations.RotateLeft(x07 + x06, 13); x05 ^= BitOperations.RotateLeft(x04 + x07, 18);
                x11 ^= BitOperations.RotateLeft(x10 + x09, 7); x08 ^= BitOperations.RotateLeft(x11 + x10, 9);
                x09 ^= BitOperations.RotateLeft(x08 + x11, 13); x10 ^= BitOperations.RotateLeft(x09 + x08, 18);
                x12 ^= BitOperations.RotateLeft(x15 + x14, 7); x13 ^= BitOperations.RotateLeft(x12 + x15, 9);
                x14 ^= BitOperations.RotateLeft(x13 + x12, 13); x15 ^= BitOperations.RotateLeft(x14 + x13, 18);
            }
            X[di + 0] += x00;
            X[di + 1] += x01;
            X[di + 2] += x02;
            X[di + 3] += x03;
            X[di + 4] += x04;
            X[di + 5] += x05;
            X[di + 6] += x06;
            X[di + 7] += x07;
            X[di + 8] += x08;
            X[di + 9] += x09;
            X[di + 10] += x10;
            X[di + 11] += x11;
            X[di + 12] += x12;
            X[di + 13] += x13;
            X[di + 14] += x14;
            X[di + 15] += x15;
        }

    }
}
