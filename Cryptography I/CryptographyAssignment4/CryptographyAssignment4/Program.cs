// Coursera Cryptography I by Dan Boneh
// Programming assignment 4 
//
// In this project you will experiment with a padding oracle attack against a toy web site hosted at crypto-class.appspot.com. 
// Padding oracle vulnerabilities affect a wide variety of products, including secure tokens (http://arstechnica.com/security/2012/06/securid-crypto-attack-steals-keys/). 
// This project will show how they can be exploited. We discussed CBC padding oracle attacks in Lecture 7.6, 
// but if you want to read more about them, please see Vaudenay's paper (http://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf). 
// 
// Now to business. Suppose an attacker wishes to steal secret information from our target web site http://crypto-class.appspot.com. 
// The attacker suspects that the web site embeds encrypted customer data in URL parameters such as this:
// http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4
// That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice. 
// The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES CBC encryption 
// with a random IV of some secret data about Alice's session. 

// After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. 
// In particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden request). 
// When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not found). 

// Armed with this information your goal is to decrypt the ciphertext listed above. 
// To do so you can send arbitrary HTTP requests to the web site of the form http://crypto-class.appspot.com/po?er="your_ciphertext_here"/
// and observe the resulting error code. The padding oracle will let you decrypt the given ciphertext one byte at a time. 
// To decrypt a single byte you will need to send up to 256 HTTP requests to the site. 
// Keep in mind that the first ciphertext block is the random IV. The decrypted message is ASCII encoded. 

// To get you started here is a short Python script (http://spark-university.s3.amazonaws.com/stanford-crypto/projects/pp4-attack_py.html) 
// that sends a ciphertext supplied on the command line to the site and prints the resulting error code. 
// You can extend this script (or write one from scratch) to implement the padding oracle attack. 
// Once you decrypt the given ciphertext, please enter the decrypted message in the box below. 

// This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC as in EAX or GCM, 
// or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it treats MAC errors.

using System;
using System.Net;
using System.Text;

namespace CryptographyAssignment4
{
    class PaddingOracle
    {
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] ConvertHexStrToBytes(String HexValue)
        {
            byte[] result = new byte[HexValue.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(HexValue.Substring(i * 2, 2), 16);
            }
            return result;
        }

        public static int GetResponseStatusCode(String requestString) //Sends http requests to crypto-class.appspot.com and gets a response code
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://crypto-class.appspot.com/po?er=" + requestString);
            HttpWebResponse response;
            HttpStatusCode respStatusCode;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                respStatusCode = response.StatusCode;
            }
            catch (WebException excp)
            {
                respStatusCode = ((HttpWebResponse)excp.Response).StatusCode;
            }
            return (int)respStatusCode;
        }

        public static String DecryptBlock(String prevBlockStr, String currBlockStr) //Implementation of padding oracle for decryption of two blocks
        {
            const int blockLength = 16;
            int responseStatusCode;
            //English characters, sorted by frequency of occurance " etaoinshrdlucmfwypvbgkqjxzETAOINSHRDLUCMFWYPVBGKQJXZ.,!/:1234567890\t\n"         
            String guessDict = "206574616f696e736872646c75636d667779707662676b716a787a4554414f494e534852444c55434d465759505642474b514a585a2e2c212f3a31323334353637383930090a";
            byte[] guessArray = ConvertHexStrToBytes(guessDict); 
            byte[] message = new byte[blockLength];
            byte[] prevBlock = ConvertHexStrToBytes(prevBlockStr);
            byte[] prevBlockTemp = ConvertHexStrToBytes(prevBlockStr);
            for (int currByte = blockLength - 1; currByte >= 0; currByte--) //For each byte in the block, starting form the last
            {
                for (int i = 0; i < guessArray.Length; i++) //We take one of the possible characters in the message
                {
                    for (int j = 1; j < (blockLength - currByte) + 1; j++) //For bytes from the end of block to the current byte
                    {
                        if (blockLength - j > currByte) //If that is not the current byte that we are guessing
                        { // We xor corresponding bytes from the previous block with already guessed bytes and with padding
                            prevBlockTemp[blockLength - j] = Convert.ToByte(prevBlock[blockLength - j] ^ message[blockLength - j] ^ (blockLength - currByte));
                        }
                        else //If that is the current byte that we are guessing
                        { // We xor corresponding byte from the previous block with our guess and with padding
                            prevBlockTemp[blockLength - j] = Convert.ToByte(prevBlock[blockLength - j] ^ guessArray[i] ^ (blockLength - currByte));
                        }
                    } //Then we send a request to crypto-class.appspot.com to check whether or not we have guessed correctly
                    responseStatusCode = GetResponseStatusCode(ByteArrayToString(prevBlockTemp) + currBlockStr);
                    if (responseStatusCode == 404 || responseStatusCode == 200) //If the padding was ok, server returns 404 or 200 status code
                    {
                        Console.WriteLine("\n" + "Successful guess");
                        message[currByte] = guessArray[i];
                        break;
                    }
                    else
                    {
                        Console.Write(".");
                    }
                }
            }
            Console.WriteLine("Block is decrypted");
            return Encoding.ASCII.GetString(message);
        }

        static void Main()
        {
            //"f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"
            String requestedText = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
            String decryptedMessage = "";
            String prevBlockStr, currBlockStr;
            const int blockLength = 16;
            for (int i = 0; i < requestedText.Length / blockLength / 2 - 1; i++) //We decrypt all blocks except the first
            {
                prevBlockStr = requestedText.Substring(i * blockLength * 2, blockLength * 2);
                currBlockStr = requestedText.Substring(i * blockLength * 2 + blockLength * 2, blockLength * 2);
                decryptedMessage += DecryptBlock(prevBlockStr, currBlockStr);
            }
            Console.WriteLine("Decrypted message is:\n" + decryptedMessage);
        }
    }
}
