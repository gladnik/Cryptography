// Coursera Cryptography I by Dan Boneh
// Programming assignment 2
//
// In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR). 
// In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext. 
// For CBC encryption we use the PKCS5 padding scheme discussed in class (13:50). 
// 
// While we ask that you implement both encryption and decryption, we will only test the decryption function. 
// In the following questions you are given an AES key and a ciphertext (both are hex encoded) and your goal is to recover the plaintext 
// and enter it in the input boxes provided below. 
//
// For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other. 
// While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself. 

using System;
using System.Text;
using System.Security.Cryptography;

namespace CryptographyAssignment2
{
    class AES_CBC_CTR
    {
        public static byte[] XorTwoByteArrays(byte[] bArray1, byte[] bArray2)
        {
            int shortestLength = (bArray1.Length < bArray2.Length) ? bArray1.Length : bArray2.Length;
            byte[] result = new byte[shortestLength];
            for (int i = 0; i < shortestLength; i++)
            {
                result[i] = Convert.ToByte(bArray1[i] ^ bArray2[i]);
            }
            return result;
        }

        public static byte[] ConvertHexStrToBytes(string HexValue)
        {
            byte[] result = new byte[HexValue.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(HexValue.Substring(i * 2, 2), 16);
            }
            return result;
        }

        public static byte[] EncryptAESBlock(byte[] key, byte[] plaintext) //Encrypts 16 bytes block with AES-128 ECB mode, without padding.
        {
            byte[] ciphertext = new byte[plaintext.Length];
            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                encryptor.TransformBlock(plaintext, 0, plaintext.Length, ciphertext, 0);
            }
            return ciphertext;
        }

        public static byte[] DecryptAESBlock(byte[] key, byte[] ciphertext) //Decrypts 16 bytes block with AES-128 ECB mode, without padding.
        {
            byte[] plaintext = new byte[ciphertext.Length];
            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                decryptor.TransformBlock(ciphertext, 0, ciphertext.Length, plaintext, 0);
            }
            return plaintext;
        }

        public static byte[] EncryptCBC(byte[] key, byte[] iv, byte[] plaintext) //AES-128 CBC encryption implementation.
        {
            int blockLength = 16, blockCounter = 0;
            byte[] ciphertext = new byte[plaintext.Length + iv.Length];
            byte[] lastBlock = new byte[blockLength];
            byte[] currBlock = new byte[blockLength];
            bool dummyBlockNeeded = true;
            byte[] dummyBlock = new byte[] { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };
            currBlock = EncryptAESBlock(key, iv); //We encrypt IV.
            currBlock.CopyTo(ciphertext, 0); //And put it to the beginning of the ciphertext.
            while (plaintext.Length > 0)
            {
                blockCounter++;
                currBlock.CopyTo(lastBlock, 0); //Set the walue of previous block.
                if (plaintext.Length >= blockLength) //Check if there are enough bytes in plaintext for the block.
                {
                    Array.Copy(plaintext, 0, currBlock, 0, blockLength); //If so, we copy them to current block.
                    Array.Copy(plaintext, blockLength, plaintext, 0, plaintext.Length - blockLength); //And remove them from the plaintext.
                    Array.Resize(ref plaintext, plaintext.Length - blockLength);
                }
                else
                {
                    dummyBlockNeeded = false;
                    int dummyValue = blockLength - plaintext.Length;
                    Array.Copy(plaintext, 0, currBlock, 0, plaintext.Length);  //Otherwise we copy the remaining bytes.
                    Array.Resize(ref plaintext, 0);
                    Array.Resize(ref ciphertext, (blockCounter + 1) * blockLength);
                    for (int i = 0; i < dummyValue; i++) //And add padding.
                    {
                        currBlock[blockLength - dummyValue + i] = Convert.ToByte(dummyValue);
                    }
                }
                currBlock = XorTwoByteArrays(currBlock, lastBlock); //Then we xor current and previous blocks.
                currBlock = EncryptAESBlock(key, currBlock); //Encrypt the result
                Array.Copy(currBlock, 0, ciphertext, blockCounter * blockLength, currBlock.Length); //And append it to the ciphertext.
            }
            if (dummyBlockNeeded) //We add the whole dummy block if needed.
            {
                blockCounter++;
                currBlock.CopyTo(lastBlock, 0);
                dummyBlock.CopyTo(currBlock, 0);
                currBlock = XorTwoByteArrays(currBlock, lastBlock);
                currBlock = EncryptAESBlock(key, currBlock);
                Array.Resize(ref ciphertext, ciphertext.Length + blockLength);
                Array.Copy(currBlock, 0, ciphertext, blockCounter * blockLength, blockLength);
            }
            return ciphertext;
        }

        public static byte[] DecryptCBC(byte[] key, byte[] iv, byte[] ciphertext) //AES-128 CBC decryption implementation.
        {
            int blockLength = 16, blockCounter = ciphertext.Length / blockLength, stepCounter = 0;
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] lastBlock = new byte[blockLength];
            byte[] currBlock = new byte[blockLength];
            iv = EncryptAESBlock(key, iv); //IV is taken as input unencrypted, so we encrypt it.
            iv.CopyTo(lastBlock, 0); //And use as a previous block.
            while (blockCounter > 0)
            {
                Array.Copy(ciphertext, stepCounter * blockLength, currBlock, 0, blockLength); //We take the current block from ciphertext.
                currBlock = DecryptAESBlock(key, currBlock); //Decrypt it.
                currBlock = XorTwoByteArrays(currBlock, lastBlock); //Xor with previous.
                Array.Copy(currBlock, 0, plaintext, stepCounter * blockLength, blockLength); //And put the result to plaintext.
                Array.Copy(ciphertext, stepCounter * blockLength, lastBlock, 0, blockLength); //Set the values of the previous block.
                blockCounter--;
                stepCounter++;
            }
            int dummyValue = plaintext[plaintext.Length - 1];
            for (int i = 0; i < dummyValue; i++) //Remove padding.
            {
                plaintext[plaintext.Length - 1 - i] = 0;
            }
            return plaintext;
        }

        public static byte[] IncrementIV(byte[] iv) //Returns IV+1
        {
            int transf = 1, counter = 0;
            do
            {
                if (iv[iv.Length - counter - 1] == 255)
                {
                    iv[iv.Length - counter - 1] = 0;
                }
                else
                {
                    iv[iv.Length - counter - 1]++;
                    transf--;
                }
                counter++;
                if (counter >= iv.Length)
                {
                    counter = 0;
                }
            }
            while (transf != 0);
            return iv;
        }

        public static byte[] EncryptCTR(byte[] key, byte[] iv, byte[] plaintext) //AES-128 CTR encryption implementation.
        {
            int blockLength = 16, blockCounter = plaintext.Length / blockLength, extra = 0;
            if (plaintext.Length % blockLength != 0) //Calculate how many full blocks and how many bytes left.
            {
                extra = plaintext.Length - blockCounter * blockLength;
            }
            byte[] ciphertext = new byte[plaintext.Length + iv.Length];
            byte[] ctrBlock = new byte[blockLength];
            byte[] currBlock = new byte[blockLength];
            Array.Copy(iv, 0, ciphertext, 0, blockLength); //Set initial IV value.
            for (int i = 0; i < blockCounter; i++) //Firstly we encrypt full blocks.
            {
                Array.Copy(plaintext, i * blockLength, currBlock, 0, blockLength); //We take the current block from plaintext.
                iv.CopyTo(ctrBlock, 0);
                ctrBlock = EncryptAESBlock(key, ctrBlock); //Calculate F(k, IV).
                currBlock = XorTwoByteArrays(currBlock, ctrBlock); //And xor that value with current block.
                iv = IncrementIV(iv); //Calculate IV for the next step.
                Array.Copy(currBlock, 0, ciphertext, (i + 1) * blockLength, blockLength); //Append current block to ciphertext.
            }
            if (extra > 0) //If the last block is not full, encrypt the remaining bytes.
            {
                Array.Copy(plaintext, blockCounter * blockLength, currBlock, 0, extra);
                iv.CopyTo(ctrBlock, 0);
                ctrBlock = EncryptAESBlock(key, ctrBlock);
                currBlock = XorTwoByteArrays(currBlock, ctrBlock);
                Array.Copy(currBlock, 0, ciphertext, (blockCounter + 1) * blockLength, extra);
            }
            return ciphertext;
        }

        public static byte[] DecryptCTR(byte[] key, byte[] ciphertext) //AES-128 CTR decryption implementation.
        {
            int blockLength = 16, blockCounter = ciphertext.Length / blockLength, extra = 0;
            if (ciphertext.Length % blockLength != 0) //Calculate how many full blocks and how many bytes left.
            {
                extra = ciphertext.Length - blockCounter * blockLength;
            }
            byte[] plaintext = new byte[ciphertext.Length - blockLength];
            byte[] ctrBlock = new byte[blockLength];
            byte[] currBlock = new byte[blockLength];
            byte[] iv = new byte[blockLength];
            Array.Copy(ciphertext, 0, iv, 0, blockLength); //Set initial IV value.
            for (int i = 1; i < blockCounter; i++) //Firstly we decrypt full blocks.
            {
                Array.Copy(ciphertext, i * blockLength, currBlock, 0, blockLength);  //We take the current block from ciphertext.
                iv.CopyTo(ctrBlock, 0);
                ctrBlock = EncryptAESBlock(key, ctrBlock); //Calculate F(k, IV).
                currBlock = XorTwoByteArrays(currBlock, ctrBlock); //And xor that value with current block.
                iv = IncrementIV(iv); //Calculate IV for the next step.
                Array.Copy(currBlock, 0, plaintext, (i - 1) * blockLength, blockLength); //Append current block to plaintext.
            }
            if (extra > 0) //If the last block is not full, dencrypt the remaining bytes.
            {
                Array.Copy(ciphertext, blockCounter * blockLength, currBlock, 0, extra);
                iv.CopyTo(ctrBlock, 0);
                ctrBlock = EncryptAESBlock(key, ctrBlock);
                currBlock = XorTwoByteArrays(currBlock, ctrBlock);
                Array.Copy(currBlock, 0, plaintext, (blockCounter - 1) * blockLength, extra);
            }
            return plaintext;
        }

        static void Main(string[] args)
        {
            //int blockSize = 16; //bytes
            string cbckey = "140b41b22a29beb4061bda66b6747e14";
            string[] ctcbc = new string[] {
	"4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", 
	"5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"};

            string ctrkey = "36f18357be4dbd77f050515c73fcf9f2";
            string[] ctctr = new string[] {
	"69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", 
	"770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"};

            string result;
            byte[] cbcKeyBytes, ctcbcBytes, cbcIv, resCBCBytes;
            byte[] ctrKeyBytes, ctctrBytes, resCTRBytes;
            cbcKeyBytes = ConvertHexStrToBytes(cbckey);
            for (int i = 0; i < ctcbc.Length; i++)
            {
                ctcbcBytes = ConvertHexStrToBytes(ctcbc[i].Substring(32, ctcbc[0].Length - 32));
                cbcIv = ConvertHexStrToBytes(ctcbc[i].Substring(0, 32));
                resCBCBytes = DecryptCBC(cbcKeyBytes, DecryptAESBlock(cbcKeyBytes, cbcIv), ctcbcBytes);
                result = Encoding.ASCII.GetString(resCBCBytes);
                Console.WriteLine(result);
            }
            ctrKeyBytes = ConvertHexStrToBytes(ctrkey);
            for (int i = 0; i < ctctr.Length; i++)
            {
                ctctrBytes = ConvertHexStrToBytes(ctctr[i]);
                resCTRBytes = DecryptCTR(ctrKeyBytes, ctctrBytes);
                result = Encoding.ASCII.GetString(resCTRBytes);
                Console.WriteLine(result);
            }
        }
    }
}
