using System.Security.Cryptography;
using System.Text;
namespace AesRsaLab;

/// Bài 1: AES-256-CBC (IV ngẫu nhiên 16 byte được ghi ở đầu dữ liệu mã hoá)
public static class AesService
{
    public static byte[] GenerateKey()
    {
        using var a = Aes.Create();
        a.KeySize = 256;
        a.GenerateKey();
        return a.Key;
    }

    public static void SaveKey(byte[] key, string path) => File.WriteAllText(path, Convert.ToBase64String(key));

    public static byte[] LoadKey(string path)
    {
        var k = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (k.Length is not (16 or 24 or 32)) throw new Exception("Khoá AES không hợp lệ (phải 16/24/32 byte).");
        return k;
    }

    public static string EncryptText(string text, byte[] key)
    {
        using var a = Aes.Create();
        a.Key = key; a.GenerateIV();
        var ct = a.EncryptCbc(Encoding.UTF8.GetBytes(text), a.IV);
        return Convert.ToBase64String(a.IV.Concat(ct).ToArray());
    }

    public static string DecryptText(string b64, byte[] key)
    {
        var all = Convert.FromBase64String(b64);
        using var a = Aes.Create();
        a.Key = key;
        return Encoding.UTF8.GetString(a.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16)));
    }

    // Dùng stream + buffer 1MB nên file hàng GB không bị tràn RAM
    public static void EncryptFile(string src, string dst, byte[] key)
    {
        using var a = Aes.Create();
        a.Key = key; a.GenerateIV();
        using var fin = File.OpenRead(src);
        using var fout = File.Create(dst);
        fout.Write(a.IV);
        using var cs = new CryptoStream(fout, a.CreateEncryptor(), CryptoStreamMode.Write);
        fin.CopyTo(cs, 1 << 20);
    }

    public static void DecryptFile(string src, string dst, byte[] key)
    {
        using var fin = File.OpenRead(src);
        var iv = new byte[16];
        fin.ReadExactly(iv);
        using var a = Aes.Create();
        a.Key = key; a.IV = iv;
        using var cs = new CryptoStream(fin, a.CreateDecryptor(), CryptoStreamMode.Read);
        using var fout = File.Create(dst);
        cs.CopyTo(fout, 1 << 20);
    }

    /// So sánh 2 file theo từng byte
    public static bool CompareFiles(string f1, string f2)
    {
        using var a = File.OpenRead(f1);
        using var b = File.OpenRead(f2);
        if (a.Length != b.Length) return false;
        var x = new byte[1 << 20]; var y = new byte[1 << 20];
        int n;
        while ((n = a.Read(x, 0, x.Length)) > 0)
        {
            b.ReadExactly(y, 0, n);
            if (!x.AsSpan(0, n).SequenceEqual(y.AsSpan(0, n))) return false;
        }
        return true;
    }

    public static void CreateTestFile(string path, long sizeMB)
    {
        using var f = File.Create(path);
        var buf = new byte[1 << 20];
        for (long i = 0; i < sizeMB; i++) { RandomNumberGenerator.Fill(buf); f.Write(buf); }
    }
}
