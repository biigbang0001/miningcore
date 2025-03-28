   using System.Diagnostics;
   using NBitcoin;
   using NBitcoin.DataEncoders;
   using System.Text;
   using System;

   namespace Miningcore.Blockchain.Bitcoin
   {
       public static class BitcoinUtils
       {
           /// <summary>
           /// Bitcoin addresses are implemented using the Base58Check encoding of the hash of either:
           /// Pay-to-script-hash (p2sh): payload is: RIPEMD160(SHA256(redeemScript)) where redeemScript is a
           /// script the wallet knows how to spend; version byte = 0x05 (these addresses begin with the digit '3')
           /// Pay-to-pubkey-hash (p2pkh): payload is: RIPEMD160(SHA256(ECDSA_publicKey)) where
           /// ECDSA_publicKey is a public key the wallet knows the private key for; version byte = 0x00
           /// (these addresses begin with the digit '1')
           /// The resulting hash in both of these cases is always exactly 20 bytes.
           /// </summary>
           public static IDestination AddressToDestination(string address, Network expectedNetwork)
           {
               var decoded = Encoders.Base58Check.DecodeData(address);
               var networkVersionBytes = expectedNetwork.GetVersionBytes(Base58Type.PUBKEY_ADDRESS, true);
               decoded = decoded.Skip(networkVersionBytes.Length).ToArray();
               var result = new KeyId(decoded);

               return result;
           }

           public static IDestination BechSegwitAddressToDestination(string address, Network expectedNetwork)
           {
               try
               {
                   var (witVersion, witnessProgram, hrp) = DecodeBech32(address);

                   // Vérifier la version du témoin (doit être 0 pour P2WPKH)
                   if (witVersion != 0)
                       throw new FormatException($"Version de témoin Bech32 non prise en charge : {witVersion}");

                   // Créer un WitKeyId avec les données réelles
                   var result = new WitKeyId(witnessProgram);

                   // Valider que l'adresse encodée correspond à l'entrée
                   var reencodedAddress = EncodeBech32(hrp, witVersion, witnessProgram);
                   if (reencodedAddress != address)
                       throw new FormatException("L'adresse encodée ne correspond pas à l'entrée");

                   return result;
               }
               catch (Exception ex)
               {
                   throw new FormatException($"Format Bech32 invalide : {ex.Message}");
               }
           }

           public static IDestination BCashAddressToDestination(string address, Network expectedNetwork)
           {
               var bcash = NBitcoin.Altcoins.BCash.Instance.GetNetwork(expectedNetwork.ChainName);
               var trashAddress = bcash.Parse<NBitcoin.Altcoins.BCash.BTrashPubKeyAddress>(address);
               return trashAddress.ScriptPubKey.GetDestinationAddress(bcash);
           }

           public static IDestination LitecoinAddressToDestination(string address, Network expectedNetwork)
           {
               var litecoin = NBitcoin.Altcoins.Litecoin.Instance.GetNetwork(expectedNetwork.ChainName);
               var encoder = litecoin.GetBech32Encoder(Bech32Type.WITNESS_PUBKEY_ADDRESS, true);

               var decoded = encoder.Decode(address, out var witVersion);
               var result = new WitKeyId(decoded);

               Debug.Assert(result.GetAddress(litecoin).ToString() == address);
               return result;
           }

           private static (byte witVersion, byte[] witnessProgram, string hrp) DecodeBech32(string address)
           {
               const string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
               const char separator = '1';

               var parts = address.Split(new[] { separator }, 2);
               if (parts.Length != 2)
                   throw new FormatException("Adresse Bech32 invalide : format incorrect");

               var hrp = parts[0]; // "nito", "bc1", etc.
               var dataPart = parts[1]; // Reste de l'adresse après "1"

               byte[] decodedData = new byte[dataPart.Length];
               for (int i = 0; i < dataPart.Length; i++)
               {
                   int value = charset.IndexOf(dataPart[i]);
                   if (value == -1)
                       throw new FormatException($"Caractère Bech32 invalide : {dataPart[i]}");
                   decodedData[i] = (byte)value;
               }

               byte witVersion = decodedData[0];
               if (witVersion > 16)
                   throw new FormatException($"Version de témoin Bech32 non prise en charge : {witVersion}");

               byte[] dataWithoutChecksum = new byte[decodedData.Length - 6 - 1];
               Array.Copy(decodedData, 1, dataWithoutChecksum, 0, dataWithoutChecksum.Length);

               byte[] witnessProgram = ConvertBits(dataWithoutChecksum, 5, 8, false);
               if (witnessProgram.Length != 20)
                   throw new FormatException($"Programme témoin Bech32 invalide : longueur {witnessProgram.Length}, attendu 20 octets");

               return (witVersion, witnessProgram, hrp);
           }

           private static string EncodeBech32(string hrp, byte witVersion, byte[] witnessProgram)
           {
               const string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

               var data = ConvertBits(witnessProgram, 8, 5, true);
               if (data == null)
                   throw new FormatException("Échec de la conversion du programme témoin en bits 5");
               var values = new byte[data.Length + 1];
               values[0] = witVersion;
               Array.Copy(data, 0, values, 1, data.Length);

               var checksum = CreateBech32Checksum(hrp, values);
               var combined = new byte[values.Length + checksum.Length];
               Array.Copy(values, 0, combined, 0, values.Length);
               Array.Copy(checksum, 0, combined, values.Length, checksum.Length);

               var sb = new StringBuilder();
               sb.Append(hrp);
               sb.Append('1');
               foreach (var value in combined)
               {
                   sb.Append(charset[value]);
               }

               return sb.ToString();
           }

           private static byte[] CreateBech32Checksum(string hrp, byte[] values)
           {
               const int BECH32_CONST = 1;
               var hrpExpanded = ExpandHrp(hrp);
               var combined = new byte[hrpExpanded.Length + values.Length + 6];
               Array.Copy(hrpExpanded, 0, combined, 0, hrpExpanded.Length);
               Array.Copy(values, 0, combined, hrpExpanded.Length, values.Length);

               var polymod = Polymod(combined) ^ BECH32_CONST;
               var checksum = new byte[6];
               for (int i = 0; i < 6; i++)
               {
                   checksum[i] = (byte)((polymod >> (5 * (5 - i))) & 31);
               }

               return checksum;
           }

           private static byte[] ExpandHrp(string hrp)
           {
               var result = new byte[2 * hrp.Length + 1];
               for (int i = 0; i < hrp.Length; i++)
               {
                   result[i] = (byte)(hrp[i] >> 5);
                   result[i + hrp.Length + 1] = (byte)(hrp[i] & 31);
               }
               return result;
           }

           private static uint Polymod(byte[] values)
           {
               uint chk = 1;
               uint[] generator = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
               foreach (var value in values)
               {
                   uint top = chk >> 25;
                   chk = (chk & 0x1ffffff) << 5 ^ value;
                   for (int i = 0; i < 5; i++)
                   {
                       if (((top >> i) & 1) != 0)
                           chk ^= generator[i];
                   }
               }
               return chk;
           }

           private static byte[] ConvertBits(byte[] data, int fromBits, int toBits, bool pad = true)
           {
               int acc = 0;
               int bits = 0;
               var result = new System.Collections.Generic.List<byte>();
               int maxv = (1 << toBits) - 1;

               foreach (var value in data)
               {
                   if (value < 0 || value >> fromBits != 0)
                       throw new FormatException("Valeur Bech32 invalide");

                   acc = (acc << fromBits) | value;
                   bits += fromBits;

                   while (bits >= toBits)
                   {
                       bits -= toBits;
                       result.Add((byte)((acc >> bits) & maxv));
                   }
               }

               if (pad)
               {
                   if (bits > 0)
                       result.Add((byte)((acc << (toBits - bits)) & maxv));
               }
               else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0)
               {
                   throw new FormatException("Conversion Bech32 invalide : bits restants non nuls");
               }

               return result.ToArray();
           }
       }
   }
