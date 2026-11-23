using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
namespace AesRsaLab;

/// Bài 2: RSA, PEM, OAEP, SHA-256, chữ ký số
public static class RsaService
{
    public static RSA GenerateKeyPair(int bits = 2048) => RSA.Create(bits);

    // Public: "PUBLIC KEY" (X.509 SubjectPublicKeyInfo); Private: "PRIVATE KEY" (PKCS#8)
    public static void ExportPem(RSA rsa, string pubPath, string privPath)
    {
        File.WriteAllText(pubPath, rsa.ExportSubjectPublicKeyInfoPem());
        File.WriteAllText(privPath, rsa.ExportPkcs8PrivateKeyPem());
    }

    public static RSA ImportPem(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        return rsa;
    }

    static string Hex(byte[]? b) => b == null ? "(không có)" : Convert.ToHexString(b);

    public static string ShowParams(RSA rsa)
    {
        RSAParameters p;
        bool priv = true;
        try { p = rsa.ExportParameters(true); } catch { p = rsa.ExportParameters(false); priv = false; }
        var sb = new StringBuilder();
        sb.AppendLine(priv ? "== PRIVATE KEY ==" : "== PUBLIC KEY ==");
        sb.AppendLine($"n (modulus, {p.Modulus!.Length * 8} bit): {Hex(p.Modulus)}");
        sb.AppendLine($"e (public exponent): {Hex(p.Exponent)}");
        if (priv)
        {
            sb.AppendLine($"d (private exponent): {Hex(p.D)}");
            sb.AppendLine($"p (số nguyên tố 1): {Hex(p.P)}");
            sb.AppendLine($"q (số nguyên tố 2): {Hex(p.Q)}");
            sb.AppendLine($"dp = d mod (p-1): {Hex(p.DP)}");
            sb.AppendLine($"dq = d mod (q-1): {Hex(p.DQ)}");
            sb.AppendLine($"qinv = q^-1 mod p: {Hex(p.InverseQ)}");
        }
        return sb.ToString();
    }

    /// Giải thích cấu trúc byte (DER/ASN.1) bên trong PEM
    public static string ExplainPem(string path)
    {
        var lines = File.ReadAllLines(path);
        var header = lines[0];
        var der = Convert.FromBase64String(string.Concat(lines.Where(l => !l.StartsWith("-----"))));
        var sb = new StringBuilder();
        sb.AppendLine($"Header: {header}  -> PEM = Base64(DER) kẹp giữa dòng BEGIN/END");
        sb.AppendLine($"Tổng {der.Length} byte DER. Cấu trúc ASN.1 (TLV = Tag-Length-Value):");
        Dump(der, 0, der.Length, 0, sb);
        sb.AppendLine("Chú thích: 30=SEQUENCE, 02=INTEGER, 05=NULL, 06=OID (2A864886F70D010101 = rsaEncryption),");
        sb.AppendLine("03=BIT STRING (chứa RSAPublicKey), 04=OCTET STRING (chứa RSAPrivateKey).");
        sb.AppendLine("PKCS#8 private: version, AlgorithmIdentifier, OCTET STRING{ version,n,e,d,p,q,dp,dq,qinv }.");
        sb.AppendLine("X.509 public: SEQUENCE{ AlgorithmIdentifier, BIT STRING{ SEQUENCE{ n, e } } }.");
        return sb.ToString();
    }

    static void Dump(byte[] d, int s, int e, int ind, StringBuilder sb)
    {
        int p = s;
        string pad = new(' ', ind * 2);
        while (p < e)
        {
            int tag = d[p++], len = d[p++];
            if (len >= 0x80) { int n = len & 0x7F; len = 0; for (int i = 0; i < n; i++) len = (len << 8) | d[p++]; }
            string name = tag switch { 0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x05 => "NULL", 0x06 => "OID", 0x04 => "OCTET STRING", 0x03 => "BIT STRING", _ => $"TAG {tag:X2}" };
            var val = d.AsSpan(p, len);
            string preview = tag is 0x02 or 0x06 ? Convert.ToHexString(val.Length > 16 ? val[..16] : val) + (val.Length > 16 ? "..." : "") : "";
            sb.AppendLine($"{pad}[{tag:X2}] {name} len={len} {preview}");
            if (tag == 0x30) Dump(d, p, p + len, ind + 1, sb);
            else if (tag == 0x04 && len > 4 && d[p] == 0x30) Dump(d, p, p + len, ind + 1, sb);
            else if (tag == 0x03 && len > 4 && d[p + 1] == 0x30) Dump(d, p + 1, p + len, ind + 1, sb);
            p += len;
        }
    }

    // Padding OAEP-SHA256: tối đa = k - 2*hLen - 2 = 256 - 64 - 2 = 190 byte (khoá 2048 bit)
    public static string Encrypt(RSA pub, byte[] data)
    {
        if (data.Length > 190) throw new Exception("Dữ liệu tối đa 190 byte với RSA-2048 + OAEP-SHA256.");
        return Convert.ToBase64String(pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
    }

    public static byte[] Decrypt(RSA priv, string b64) =>
        priv.Decrypt(Convert.FromBase64String(b64), RSAEncryptionPadding.OaepSHA256);

    /// Đánh giá tốc độ: e nhỏ (65537) vs d lớn, bằng BigInteger.ModPow (RSA thô)
    public static string Benchmark(RSA rsa, int iterations = 100)
    {
        var p = rsa.ExportParameters(true);
        var n = new BigInteger(p.Modulus!, true, true);
        var e = new BigInteger(p.Exponent!, true, true);
        var d = new BigInteger(p.D!, true, true);
        var m = new BigInteger(RandomNumberGenerator.GetBytes(100), true, true);
        BigInteger c = 0;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++) c = BigInteger.ModPow(m, e, n);
        double tE = sw.Elapsed.TotalMilliseconds / iterations;
        sw.Restart();
        BigInteger m2 = 0;
        for (int i = 0; i < iterations; i++) m2 = BigInteger.ModPow(c, d, n);
        double tD = sw.Elapsed.TotalMilliseconds / iterations;

        var data = RandomNumberGenerator.GetBytes(100);
        sw.Restart();
        string ct = "";
        for (int i = 0; i < iterations; i++) ct = Encrypt(rsa, data);
        double lE = sw.Elapsed.TotalMilliseconds / iterations;
        sw.Restart();
        for (int i = 0; i < iterations; i++) Decrypt(rsa, ct);
        double lD = sw.Elapsed.TotalMilliseconds / iterations;

        return $"e = {e} ({p.Exponent!.Length * 8} bit), d = {p.D.Length * 8} bit, {iterations} lần\n" +
               $"ModPow thô  : mã hoá (n,e) {tE:F4} ms | giải mã (n,d) {tD:F4} ms | d/e = {tD / tE:F1}x | đúng: {m == m2}\n" +
               $"Thư viện RSA: Encrypt {lE:F4} ms | Decrypt {lD:F4} ms | Decrypt/Encrypt = {lD / lE:F1}x\n" +
               "=> Public key (e nhỏ) rất nhanh; private key (d to) chậm hơn nhiều chục lần.";
    }

    // ---- Bài 8: SHA-256 ----
    public static byte[] Sha256(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));

    public static string Avalanche(string a, string b)
    {
        var h1 = Sha256(a); var h2 = Sha256(b);
        int diff = h1.Zip(h2, (x, y) => BitOperations.PopCount((uint)(x ^ y))).Sum();
        return $"SHA256(a) = {Convert.ToHexString(h1)}\nSHA256(b) = {Convert.ToHexString(h2)}\n" +
               $"Số bit khác nhau: {diff}/256 ({diff / 2.56:F1}%) -> hiệu ứng thác lũ (~50% là lý tưởng)";
    }

    // ---- Bài 9: Chữ ký số ----
    public static byte[] SignPkcs1(RSA priv, byte[] data) => priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    public static byte[] SignPss(RSA priv, byte[] data) => priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    public static bool VerifyPkcs1(RSA pub, byte[] data, byte[] sig) => pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    public static bool VerifyPss(RSA pub, byte[] data, byte[] sig) => pub.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
}
