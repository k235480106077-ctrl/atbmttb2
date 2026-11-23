using System.Diagnostics;
using System.Text;
using AesRsaLab;

Console.OutputEncoding = Encoding.UTF8;
byte[]? aesKey = null;
System.Security.Cryptography.RSA? rsa = null;

string Ask(string p) { Console.Write(p + ": "); return Console.ReadLine()?.Trim().Trim('"') ?? ""; }
void NeedAes() { if (aesKey == null) throw new Exception("Chưa có khoá AES (chọn 1 hoặc 3)."); }
void NeedRsa() { if (rsa == null) throw new Exception("Chưa có khoá RSA (chọn 11 hoặc 14/15)."); }

while (true)
{
    Console.WriteLine("""

    ===== BÀI 1: AES =====
     1. Sinh khoá AES-256        2. Lưu khoá ra file      3. Import khoá từ file
     4. Mã hoá văn bản (in màn hình)  5. Giải mã văn bản
     6. Mã hoá file               7. Giải mã file
     8. Thử nghiệm file lớn (thời gian + so sánh byte)
    ===== BÀI 2: RSA =====
    11. Sinh cặp khoá RSA        12. Xuất PEM             13. Xem cấu trúc PEM
    14. Import public PEM (n,e)  15. Import private PEM (n,e,d,...)
    16. Mã hoá (<=190 byte -> base64 -> file)   17. Giải mã từ file
    18. Đánh giá tốc độ (e nhỏ vs d lớn)
    19. SHA-256 + hiệu ứng thác lũ
    20. Chữ ký số: PKCS#1 v1.5 (tất định) vs PSS (ngẫu nhiên)
     0. Thoát
    """);
    var c = Ask("Chọn");
    try
    {
        switch (c)
        {
            case "0": return;
            case "1": aesKey = AesService.GenerateKey(); Console.WriteLine("Khoá (base64): " + Convert.ToBase64String(aesKey)); break;
            case "2": NeedAes(); AesService.SaveKey(aesKey!, Ask("File lưu khoá")); Console.WriteLine("Đã lưu."); break;
            case "3": aesKey = AesService.LoadKey(Ask("File khoá")); Console.WriteLine("Đã import khoá " + aesKey.Length * 8 + " bit."); break;
            case "4": NeedAes(); Console.WriteLine(AesService.EncryptText(Ask("Văn bản"), aesKey!)); break;
            case "5": NeedAes(); Console.WriteLine(AesService.DecryptText(Ask("Base64"), aesKey!)); break;
            case "6": NeedAes(); AesService.EncryptFile(Ask("File nguồn"), Ask("File đích"), aesKey!); Console.WriteLine("Xong."); break;
            case "7": NeedAes(); AesService.DecryptFile(Ask("File mã hoá"), Ask("File đích"), aesKey!); Console.WriteLine("Xong."); break;
            case "8":
            {
                NeedAes();
                var src = Ask("File lớn (Enter = tạo file ngẫu nhiên)");
                if (src == "")
                {
                    src = "test_big.bin";
                    long mb = long.Parse(Ask("Kích thước (MB), vd 1024"));
                    AesService.CreateTestFile(src, mb);
                }
                var enc = src + ".enc"; var dec = src + ".dec";
                var sw = Stopwatch.StartNew(); AesService.EncryptFile(src, enc, aesKey!); var t1 = sw.Elapsed.TotalSeconds;
                sw.Restart(); AesService.DecryptFile(enc, dec, aesKey!); var t2 = sw.Elapsed.TotalSeconds;
                double mb2 = new FileInfo(src).Length / 1048576.0;
                bool same = AesService.CompareFiles(src, dec);
                Console.WriteLine($"Kích thước: {mb2:F1} MB\nMã hoá: {t1:F2}s ({mb2 / t1:F0} MB/s)\nGiải mã: {t2:F2}s ({mb2 / t2:F0} MB/s)\nSo sánh byte nguồn vs giải mã: {(same ? "GIỐNG NHAU" : "KHÁC NHAU")}");
                break;
            }
            case "11": rsa = RsaService.GenerateKeyPair(2048); Console.WriteLine(RsaService.ShowParams(rsa)); break;
            case "12": NeedRsa(); RsaService.ExportPem(rsa!, Ask("File public.pem"), Ask("File private.pem")); Console.WriteLine("Đã xuất."); break;
            case "13": Console.WriteLine(RsaService.ExplainPem(Ask("File PEM"))); break;
            case "14": case "15": rsa = RsaService.ImportPem(Ask("File PEM")); Console.WriteLine(RsaService.ShowParams(rsa)); break;
            case "16":
            {
                NeedRsa();
                var data = Encoding.UTF8.GetBytes(Ask("Dữ liệu (<=190 byte)"));
                var b64 = RsaService.Encrypt(rsa!, data);
                File.WriteAllText(Ask("File lưu kết quả"), b64);
                Console.WriteLine(b64);
                break;
            }
            case "17":
            {
                NeedRsa();
                var plain = RsaService.Decrypt(rsa!, File.ReadAllText(Ask("File chứa base64")).Trim());
                Console.WriteLine("Kết quả: " + Encoding.UTF8.GetString(plain));
                var orig = Ask("Nhập lại dữ liệu gốc để so sánh (Enter = bỏ qua)");
                if (orig != "") Console.WriteLine(plain.SequenceEqual(Encoding.UTF8.GetBytes(orig)) ? "KHỚP với nguồn" : "KHÔNG khớp");
                break;
            }
            case "18": NeedRsa(); Console.WriteLine(RsaService.Benchmark(rsa!)); break;
            case "19": Console.WriteLine(RsaService.Avalanche(Ask("Chuỗi A"), Ask("Chuỗi B (sửa 1 ký tự)"))); break;
            case "20":
            {
                NeedRsa();
                var msg = Encoding.UTF8.GetBytes(Ask("Dữ liệu cần ký"));
                var p1 = RsaService.SignPkcs1(rsa!, msg); var p2 = RsaService.SignPkcs1(rsa!, msg);
                var s1 = RsaService.SignPss(rsa!, msg); var s2 = RsaService.SignPss(rsa!, msg);
                Console.WriteLine($"PKCS#1 v1.5: 2 lần ký GIỐNG nhau? {p1.SequenceEqual(p2)}");
                Console.WriteLine($"PSS        : 2 lần ký GIỐNG nhau? {s1.SequenceEqual(s2)}");
                Console.WriteLine($"PSS chữ ký 1: {Convert.ToBase64String(s1)[..60]}...");
                Console.WriteLine($"PSS chữ ký 2: {Convert.ToBase64String(s2)[..60]}...");
                Console.WriteLine($"Verify PSS 1: {RsaService.VerifyPss(rsa!, msg, s1)} | Verify PSS 2: {RsaService.VerifyPss(rsa!, msg, s2)}");
                break;
            }
            default: Console.WriteLine("Lựa chọn không hợp lệ."); break;
        }
    }
    catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
}
