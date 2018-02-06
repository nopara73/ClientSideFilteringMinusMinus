# Client Side Filtering--

## Abstract

This document describes a client side filtering protocol for Bitcoin light clients. Client Side Filtering-- is inspired by [Compact Client Side Filtering for Light Clients](https://github.com/Roasbeef/bips/blob/master/gcs_light_client.mediawiki) and changes it into a centralized, simplistic system. The goal of this scheme is to simplify the protocol to avoid implementation complexity, improve wallet useability, while preserving privacy. Most Bitcoin wallet providers today have their own back end, where they can monitor every transaction of their users. Such wallet providers may consider changing to this model.

## Server Side

The server is trusted.

The server must run a Bitcoin full node and maintain filters. The filter talbe must contain a list of block heights with the corresponding block hashes and scriptPubKeys.

![](https://i.imgur.com/oYHnLcP.png)

This filter table is deterministic and is served to all wallet clients. The server must be able to serve filters partially, too.
**The list of scriptPubKeys must not only contain those scriptPubKeys that are corresponding to the outputs being spent to, but also the inputs being spent from.**

| Request         | Parameters   | Description                                                                   |
|-----------------|--------------|-------------------------------------------------------------------------------|
| lastBlockHeight |              |                                                                               |
| filtersFrom     | blockHeight  | The server serves the client with the filter from the specified blockHeight   |
| filters         | blockHeights | The server serves the client with filters corresponding to the blockHeights   |
| filter          | blockHeight  | The server serves the client with the filter corresponding to the blockHeight |

The client may only request the filter from the creation of the wallet.

### Problem: Filters Too Big

In the current form of the scheme the filters are just as big as the Bitcoin blockchain, which defeats the purpose of this scheme.  
In order to lower the size of the filters, instead of scriptPubKeys, the hash of the scriptPubKeys must maintained and forwarded to the client. The client knows what it is looking for, so it can just as easily compare hashes.

```cs
using (SHA1Managed sha1 = new SHA1Managed())
{
     var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(input));
     return new String(Convert.ToBase64String(hash).Take(4).ToArray());
}
```

A filter is serialized as follows: `{blockHeight}:{blockHash}\n{list of scriptPubKey hashes}\n`.  

In this case the filters are roughly 60 times smaller than the whole blockchain and 1GB results in roughly 100 scriptPubKey hash collision. From a privacy point of view some scriptPubKey hash collision is preferable, since more blocks would be examined by the user, yet it's still unlikely the users' scriptPubKeys would collide with other users.

Through gzip compressing the serialized file we can further lower the final filter file by 30%.  

Today the Bitcoin blockchain is 150GB. This means the compressed filters would be around 1.75GB.

#### Further Efficiency

Using Golomb-Rice coding and other techniques, as described in the BIP: [Compact Client Side Filtering for Light Clients](https://github.com/Roasbeef/bips/blob/master/gcs_light_client.mediawiki) can result in further efficiency gain. Combining this document with that approach the filters may be under 500MB in expense of additional complexity.

## Client Side

The client maintains its own wallet and its own transactions on the disk, therefore it knows which scriptPubKeys it may be interested in. After syncing the filters, the client can figure out which blocks it needs to have in order to establish its wallet balance, build transactions, etc. The client then downloads the blocks it needs from the Bitcoin peer to peer network (or from any source), it computes the block hash and compares it to the expected block hash, which can be found in the filter and goes on with its life.

## Proof Of Concept - Proving The Numbers
```cs
using NBitcoin;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FilterTest
{
    class Program
    {
        public static RPCClient RpcClient;

    #pragma warning disable IDE1006 // Naming Styles
        static async Task Main(string[] args)
    #pragma warning restore IDE1006 // Naming Styles
        {
            try
            {
                var filtersFileName = "Filters.dat";

                await InitializeEverythingAsync(filtersFileName);

                var collisions = 0;
                var bestBlockHeight = RpcClient.GetBlockCount();
                long chainSize = 0;
                var utxoSet = new Dictionary<(uint256 txid, int n), TxOut>();
                //for (int i = 407000; i < 407701; i++) // nice full blocks here
                //for (int i = 220000; i < bestBlockHeight; i++) // 220000 height is when the blockchain started to grow (2013)
                for (int i = 0; i < bestBlockHeight; i++) // blocks from the beginning of times
                {
                    var scriptPubKeys = new HashSet<string>();
                    var hashes = new HashSet<string>();
                    Block block = await RpcClient.GetBlockAsync(i);

                    foreach (var tx in block.Transactions)
                    {
                        for (int k = 0; k < tx.Outputs.Count; k++)
                        {
                            var output = tx.Outputs[k];
                            if(!utxoSet.TryAdd((tx.GetHash(), k), output)) // for some reason it fails once in a while
                            {
                                Console.WriteLine($"Ignoring: utxoSet already contains: {tx.GetHash()} {k}.");
                            }
                            string hex = output.ScriptPubKey.ToHex();
                            scriptPubKeys.Add(hex);
                            var hash = GenerateShortSha1Hash(hex);
                            hashes.Add(hash);
                        }

                        if (!tx.IsCoinBase)
                        {
                            foreach (var input in tx.Inputs)
                            {
                                var found = utxoSet.Single(x => x.Key.txid == input.PrevOut.Hash && x.Key.n == input.PrevOut.N);
                                TxOut prevTxOut = found.Value;

                                var hex = prevTxOut.ScriptPubKey.ToHex();
                                scriptPubKeys.Add(hex);
                                var hash = GenerateShortSha1Hash(hex);
                                hashes.Add(hash);

                                utxoSet.Remove(found.Key);
                            }
                        }
                    }

                    collisions += scriptPubKeys.Count - hashes.Count;
                    chainSize += block.GetSerializedSize();
                    if (i % 1000 == 0)
                    {
                        var chainSizeMb = chainSize / 1024 / 1024;
                        if (chainSizeMb > 1024)
                        {
                            Console.WriteLine($"Height: {i}, collisions: {collisions}, chain size: {chainSize / 1024 / 1024 / 1024} GB");
                        }
                        else
                        {
                            Console.WriteLine($"Height: {i}, collisions: {collisions}, chain size: {chainSize / 1024 / 1024} MB");
                        }
                    }

                    var builder = new StringBuilder();
                    builder.Append(i);
                    builder.Append(":");
                    builder.Append(block.GetHash());
                    builder.Append("\n");
                    foreach (var scp in hashes)
                    {
                        builder.Append(scp);
                    }
                    builder.Append("\n");

                    var filter = builder.ToString();
                    await File.AppendAllTextAsync(filtersFileName, filter);
                }

                Console.WriteLine($"Collisions:{collisions}");

                var fi = new FileInfo(filtersFileName);

                using (FileStream inFile = fi.OpenRead())
                {
                    // Prevent compressing hidden and 
                    // already compressed files.
                    if ((File.GetAttributes(fi.FullName)
                        & FileAttributes.Hidden)
                        != FileAttributes.Hidden & fi.Extension != ".gz")
                    {
                        // Create the compressed file.
                        using (FileStream outFile =
                                    File.Create(fi.FullName + ".gz"))
                        {
                            using (GZipStream Compress =
                                new GZipStream(outFile,
                                CompressionMode.Compress))
                            {
                                // Copy the source file into 
                                // the compression stream.
                                inFile.CopyTo(Compress);

                                Console.WriteLine("Compressed {0} from {1} to {2} bytes.",
                                    fi.Name, fi.Length.ToString(), outFile.Length.ToString());
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            Console.WriteLine();
            Console.WriteLine("Press a key to exit...");
            Console.ReadKey();
        }

        private static async Task InitializeEverythingAsync(string filtersFileName)
        {
            if (File.Exists(filtersFileName))
            {
                File.Delete(filtersFileName);
            }

            RpcClient = new RPCClient(
            credentials: new RPCCredentialString
            {
                UserPassword = new NetworkCredential("username", "password")
            },
            network: Network.Main);
            await AssertRpcNodeFullyInitializedAsync();
            Console.WriteLine("Bitcoin Core is running and fully initialized.");
        }

        /// <summary>
        /// Quickly generates a short, relatively unique hash
        /// https://codereview.stackexchange.com/questions/102251/short-hash-generator
        /// </summary>
        public static string GenerateShortSha1Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(input));

                return new String(Convert.ToBase64String(hash).Take(4).ToArray());
            }
        }

        private static async Task AssertRpcNodeFullyInitializedAsync()
        {
            RPCResponse blockchainInfo = await RpcClient.SendCommandAsync(RPCOperations.getblockchaininfo);
            try
            {
                if (blockchainInfo.Error != null)
                {
                    throw new NotSupportedException("blockchainInfo.Error != null");
                }
                if (string.IsNullOrWhiteSpace(blockchainInfo?.ResultString))
                {
                    throw new NotSupportedException("string.IsNullOrWhiteSpace(blockchainInfo?.ResultString) == true");
                }
                int blocks = blockchainInfo.Result.Value<int>("blocks");
                if (blocks == 0)
                {
                    throw new NotSupportedException("blocks == 0");
                }
                int headers = blockchainInfo.Result.Value<int>("headers");
                if (headers == 0)
                {
                    throw new NotSupportedException("headers == 0");
                }
                if (blocks != headers)
                {
                    throw new NotSupportedException("blocks != headers");
                }

                var estimateSmartFeeResponse = await RpcClient.TryEstimateSmartFeeAsync(100, EstimateSmartFeeMode.Conservative);
                if (estimateSmartFeeResponse == null) throw new NotSupportedException($"estimatesmartfee {100} {EstimateSmartFeeMode.Conservative} == null");
            }
            catch
            {
                Console.WriteLine("Bitcoin Core is not yet fully initialized.");
                throw;
            }
        }
    }
}
```
