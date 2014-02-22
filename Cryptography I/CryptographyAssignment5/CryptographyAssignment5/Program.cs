// Coursera Cryptography I by Dan Boneh
// Programming assignment 5
// 
// Your goal this week is to write a program to compute discrete log modulo a prime p. 
// Let g be some element in (Z_p)* and suppose you are given h in (Z_p)* such that h = g^x where 1 <= x <= 2^40. 
// Your goal is to find x. More precisely, the input to your program is p, g, h and the output is x. 
// 
// The trivial algorithm for this problem is to try all 2^40 possible values of x until the correct one is found, 
// that is until we find an x satisfying h = g^x in Z_p. This requires 2^40 multiplications. 
// In this project you will implement an algorithm that runs in time roughly sqrt(2^40) = 2^20 using a meet in the middle attack. 
// 
// Let B = 2^20. Since x is less than B^2 we can write the unknown x base B as x = x_0 * B + x_1 where x_0, x_1 are in the range [0, B−1]. Then
// 
// h = g^x = g^(x_0 * B + x_1) = (g^B)^x_0 * g^x_1 in Z_p.
// 
// By moving the term g^x_1 to the other side we obtain
//
// h / g^x_1 = (g^B)^x_0 in Z_p.
//
// The variables in this equation are x_0, x_1 and everything else is known: you are given g, h and B = 2^20. 
// Since the variables x_0 and x_1 are now on different sides of the equation we can find a solution using meet in the middle (Lecture 3.3):
//      First build a hash table of all possible values of the left hand side h / g^x_1 for x_1 = 0, 1, …, 2^20.
//      Then for each value x_0 = 0, 1, 2, …, 2^20 check if the right hand side (g^B)^x_0 is in this hash table. 
//      If so, then you have found a solution (x_0, x_1) from which you can compute the required x as x = x_0 * B + x_1.
//      The overall work is about 2^20 multiplications to build the table and another 2^20 lookups in this table. 
// 
// Now that we have an algorithm, here is the problem to solve:
// 
// p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
// g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
// h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333

// Each of these three numbers is about 153 digits. Find x such that h = g^x in Z_p. 

// To solve this assignment it is best to use an environment that supports multi-precision and modular arithmetic. 
// In Python you could use the gmpy2 or numbthy modules. Both can be used for modular inversion and exponentiation. 
// In C you can use GMP. 
// In Java use a BigInteger class which can perform mod, modPow and modInverse operations.

using System;
using System.Collections;
using System.Diagnostics;
using System.Numerics;


namespace CryptographyAssignment5
{
    class DiscrLog
    {
        static void Main()
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            BigInteger p = BigInteger.Parse("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171");
            BigInteger g = BigInteger.Parse("11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568");
            BigInteger h = BigInteger.Parse("3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333");
            const int B = 1048576; //Math.Pow(2, 20)
            BigInteger tempValue;
            Console.WriteLine("Initialization: {0}", stopwatch.Elapsed);
            
            Hashtable leftTable = new Hashtable();
            BigInteger gInverse = BigInteger.ModPow(g, p - 2, p); //Fermat's Little Theorem: x^(p-1) mod p = 1   =>   x^-1 = x^(p-2)
            tempValue = h; //For x_1==0   h * g^-x_1 = h
            for (int x_1 = 0; x_1 < B; x_1++) //Building a hash table for h * g^-x_1 mod p
            {
                //We can compute (key, value) pair as hashTable[h * g^-x_1 mod p] = x_1 on each step.
                //But that works too slow, because every time we compute g^-x_1
                //Instead, we compute hash table key as key = key * g^-1 mod p
                leftTable.Add(tempValue, x_1);
                tempValue = BigInteger.Remainder(BigInteger.Multiply(tempValue, gInverse), p);
            }
            Console.WriteLine("Building hash table for h * g^-x_1 mod p: {0}", stopwatch.Elapsed);
            
            tempValue = 1; //For x_0==0   g^B^x_0 = 1
            BigInteger gPowB = BigInteger.ModPow(g, B, p);
            BigInteger result = 0;
            for (int x_0 = 0; x_0 < B; x_0++)
            {
                if (leftTable.ContainsKey(tempValue))
                {
                    int x_1 = Convert.ToInt32(leftTable[tempValue]); //leftTable[tempValue] - returns value for the key==tempValue
                    result = BigInteger.Remainder(BigInteger.Multiply(x_0, B) + x_1, p); //x = x_0 * B + x_1
                    break;
                }
                //Likewise, we can calculate g^B^x_0 each time, but instead we calculate tempValue = tempValue * g^B
                tempValue = BigInteger.Remainder(BigInteger.Multiply(tempValue, gPowB), p);
            }
            Console.WriteLine("Search in hash table: {0}", stopwatch.Elapsed);

            stopwatch.Stop();
            Console.WriteLine("Power of x is: {0}", result);
        }
    }
}
