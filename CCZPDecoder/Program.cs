using System;
using Ionic.Zlib;
using System.IO;
using System.Linq;

namespace CCZPDecoder
{
    class Program
    {
        private static bool s_bEncryptionKeyIsValid;
        private static uint[] s_uEncryptedPvrKeyParts = new uint[] { 0x72c159a2, 0x4b3f9693, 0x97bc2991, 0x8a8ef15b };
        private static uint[] s_uEncryptionKey = new uint[1024];

        static void Main(string[] args)
        {
            if(args.Length < 2)
            {
                Console.WriteLine("you must input dir and ext(eg ccz)");
                return;
            }
			//Console.Write("目录：");
			//var dir1 = Console.ReadLine();
			var dir = args[0];
            var ext = args[1];

            var outdir = dir + "_out";

			if (Directory.Exists(dir))
            {
                var files = Directory.GetFiles(dir, $"*.{ext}", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    var outfilename = Path.GetFileNameWithoutExtension(file);
                    if (Path.GetExtension(outfilename).ToLower() != ".pvr")
                    {
                        outfilename += ".pvr";
					}
                    if (File.Exists(outfilename))
                    {
                        continue;
                    }
                    var thisoutdir = Path.Combine(outdir, Path.GetDirectoryName(file));
                    if (!Directory.Exists(thisoutdir))
                    {
                        Directory.CreateDirectory(thisoutdir);
                    }
					var outpath = Path.Combine(thisoutdir, outfilename);
					var bytes = File.ReadAllBytes(file);
                    if (bytes[0] != 'C' || bytes[1] != 'C' || bytes[2] != 'Z')
                    {
                        continue;
                    }

                    byte[] decbuff;
					if (bytes[3] == 'p')
                    {
                        Console.WriteLine($"解密：{file}");
                        var enclen = (bytes.Length - 12) / 4;
                        var data = new uint[enclen];
                        for (var i = 0; i < enclen; i++)
                        {
                            data[i] = BitConverter.ToUInt32(bytes, 12 + i * 4);
                        }
						decbuff = Decode(data, enclen, bytes, out var len);
						decbuff = Decompress(decbuff, len);
					}
                    else if (bytes[3] == '!')
					{
                        var len = bytes.Length - 12;
                        decbuff = Decompress(bytes.Skip(12).ToArray(), len);
					}
                    else
                    {
						continue;
					}
                    
                    File.WriteAllBytes(outpath, decbuff);
                }
                Console.WriteLine("完成！");
                Console.Read();
            }
        }

        private static byte[] Decode(uint[] data, int len, byte[] bytes, out int dsize)
        {
            int enclen = 1024;
            int securelen = 512;
            int distance = 64;
            // create long key
            if (!s_bEncryptionKeyIsValid)
            {
                uint y = 0;
                uint p = 0;
                uint e = 0;
                uint rounds = 6;
                uint sum = 0;
                uint z = s_uEncryptionKey[enclen - 1];
                uint DELTA = 0x9e3779b9;
                uint MX;
                do
                {
                    sum += DELTA;
                    e = (sum >> 2) & 3;

                    for (p = 0; p < enclen - 1; p++)
                    {
                        y = s_uEncryptionKey[p + 1];
                        MX = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (s_uEncryptedPvrKeyParts[(p & 3) ^ e] ^ z)));
                        z = s_uEncryptionKey[p] += MX;
                    }

                    y = s_uEncryptionKey[0];
                    MX = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (s_uEncryptedPvrKeyParts[(p & 3) ^ e] ^ z)));
                    z = s_uEncryptionKey[enclen - 1] += MX;

                } while (--rounds > 0);
                s_bEncryptionKeyIsValid = true;
            }
            int b = 0;
            int i = 0;
            // encrypt first part completely
            for (; i < len && i < securelen; i++)
            {
                data[i] ^= s_uEncryptionKey[b++];

                if (b >= enclen)
                {
                    b = 0;
                }
            }
            // encrypt second section partially
            for (; i < len; i += distance)
            {
                data[i] ^= s_uEncryptionKey[b++];

                if (b >= enclen)
                {
                    b = 0;
                }
            }
            // 
            var mod = bytes.Length % 4;
            var buffer = new byte[len * 4 - 4 + mod];
            dsize = BitConverter.ToInt32((BitConverter.GetBytes(data[0]).Reverse().ToArray()), 0);
            for (i = 0; i < len - 1; i++)
            {
                BitConverter.GetBytes(data[i + 1]).CopyTo(buffer, i * 4);
            }
            for (i = buffer.Length - mod; i < buffer.Length; i++)
            {
                buffer[i] = bytes[i + 16];
            }
            return buffer;
        }

        private static byte[] Decompress(byte[] data, int len)
        {
            using (var stream = new ZlibStream(new MemoryStream(data), CompressionMode.Decompress))
            {
                var buffer = new byte[len];
                stream.Read(buffer, 0, len);
                return buffer;
            }
        }
    }
}
