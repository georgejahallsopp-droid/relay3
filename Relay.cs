// Relay: move files between your devices over your own Wi-Fi.
// Build with build.bat (uses the C# compiler built into Windows), then run Relay.exe.
// Written for C# 5 / .NET Framework 4, which ships with Windows 10 and 11.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace Relay
{
    public class UserRec
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Salt { get; set; }
        public string Hash { get; set; }
        public long Created { get; set; }
    }

    public class SessionRec
    {
        public string Token { get; set; }
        public string UserId { get; set; }
        public long Created { get; set; }
    }

    public class FileRec
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public string Name { get; set; }
        public long Size { get; set; }
        public string Type { get; set; }
        public string Device { get; set; }
        public long Created { get; set; }
    }

    public class Db
    {
        public List<UserRec> Users { get; set; }
        public List<SessionRec> Sessions { get; set; }
        public List<FileRec> Files { get; set; }
        public Db()
        {
            Users = new List<UserRec>();
            Sessions = new List<SessionRec>();
            Files = new List<FileRec>();
        }
    }

    class Request
    {
        public string Method;
        public string Path;
        public string Query;
        public Dictionary<string, string> Headers;
        public long ContentLength;
        public bool HasContentLength;
        public Stream Body;
    }

    static class Program
    {
        const string CookieName = "relay_session";
        const long SpareBytes = 200L * 1024 * 1024; // always leave this much disk free
        const int PasswordIterations = 150000;

        static readonly object Gate = new object();
        static readonly Dictionary<string, long> Versions = new Dictionary<string, long>();
        static readonly Regex IdPattern = new Regex("^[0-9a-f]{32}$");
        static readonly Regex TypePattern = new Regex(@"^[A-Za-z0-9.+\-]+/[A-Za-z0-9.+\-]+$");

        static Db db = new Db();
        static string DataDir, FilesDir, DbPath;
        static int Port = 8000;
        static long StartVersion;
        static long VersionCounter;
        static byte[] PageBytes;

        static int Main(string[] args)
        {
            Console.Title = "Relay";
            DataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RelayData");
            FilesDir = Path.Combine(DataDir, "files");
            DbPath = Path.Combine(DataDir, "db.json");
            Directory.CreateDirectory(FilesDir);
            LoadDb();
            CleanPartials();

            StartVersion = Now();
            VersionCounter = StartVersion;

            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--port") int.TryParse(args[i + 1], out Port);
            }

            using (var res = typeof(Program).Assembly.GetManifestResourceStream("Relay.index.html"))
            {
                if (res == null)
                {
                    Console.WriteLine("index.html wasn't built into Relay.exe. Run build.bat again.");
                    Console.ReadLine();
                    return 1;
                }
                var ms = new MemoryStream();
                res.CopyTo(ms);
                PageBytes = ms.ToArray();
            }

            TcpListener listener;
            try
            {
                listener = new TcpListener(IPAddress.Any, Port);
                listener.Start();
            }
            catch (SocketException)
            {
                Console.WriteLine("Port " + Port + " is already in use. Relay may already be running in another window.");
                Console.WriteLine("To use a different port, run:  Relay.exe --port 8001");
                Console.ReadLine();
                return 1;
            }

            var acceptThread = new Thread(() => AcceptLoop(listener));
            acceptThread.IsBackground = true;
            acceptThread.Start();

            PrintBanner();
            try { Process.Start("http://localhost:" + Port + "/"); } catch { }

            CommandLoop();
            return 0;
        }

        static void PrintBanner()
        {
            Console.WriteLine();
            Console.WriteLine("  Relay is running.");
            Console.WriteLine();
            Console.WriteLine("  On this computer:   http://localhost:" + Port);
            var addrs = Addresses();
            if (addrs.Count == 0)
            {
                Console.WriteLine("  On other devices:   (not connected to a network)");
            }
            else
            {
                Console.WriteLine("  On other devices:   http://" + addrs[0] + ":" + Port + "   (same Wi-Fi)");
                for (int i = 1; i < addrs.Count; i++)
                    Console.WriteLine("                      http://" + addrs[i] + ":" + Port);
            }
            Console.WriteLine();
            Console.WriteLine("  Keep this window open while you use Relay.");
            Console.WriteLine("  Files are saved in: " + FilesDir);
            Console.WriteLine();
            Console.WriteLine("  Commands:  reset  (change an account's password)   users  (list accounts)");
            Console.WriteLine();
        }

        // ---------------- console commands ----------------

        static void CommandLoop()
        {
            while (true)
            {
                Console.Write("> ");
                string line = Console.ReadLine();
                if (line == null) { Thread.Sleep(Timeout.Infinite); return; }
                line = line.Trim().ToLowerInvariant();
                if (line == "") continue;
                if (line == "users") ListUsers();
                else if (line == "reset") ResetPassword();
                else if (line == "help") PrintBanner();
                else Console.WriteLine("  Type reset, users or help.");
            }
        }

        static void ListUsers()
        {
            lock (Gate)
            {
                if (db.Users.Count == 0) { Console.WriteLine("  No accounts yet."); return; }
                foreach (var u in db.Users)
                {
                    int n = db.Files.Count(f => f.UserId == u.Id);
                    Console.WriteLine("  " + u.Email + "  (" + n + " file" + (n == 1 ? "" : "s") + ")");
                }
            }
        }

        static void ResetPassword()
        {
            Console.Write("  Account email: ");
            string email = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
            UserRec user;
            lock (Gate) user = db.Users.FirstOrDefault(u => u.Email == email);
            if (user == null) { Console.WriteLine("  No account uses that email."); return; }

            Console.Write("  New password: ");
            string pw = ReadSecret();
            if (pw.Length < 8) { Console.WriteLine("  Use at least 8 characters. Password not changed."); return; }
            Console.Write("  Type it again: ");
            if (ReadSecret() != pw) { Console.WriteLine("  Passwords didn't match. Password not changed."); return; }

            string salt = RandomHex(16);
            string hash = HashPassword(pw, salt);
            lock (Gate)
            {
                user.Salt = salt;
                user.Hash = hash;
                db.Sessions.RemoveAll(s => s.UserId == user.Id);
                SaveDb();
                Bump(user.Id);
            }
            Console.WriteLine("  Password changed. That account has been signed out everywhere.");
        }

        static string ReadSecret()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0) { sb.Length--; Console.Write("\b \b"); }
                    continue;
                }
                if (!char.IsControl(key.KeyChar)) { sb.Append(key.KeyChar); Console.Write("*"); }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        // ---------------- HTTP plumbing ----------------

        static void AcceptLoop(TcpListener listener)
        {
            while (true)
            {
                TcpClient client;
                try { client = listener.AcceptTcpClient(); }
                catch (SocketException) { continue; }
                var t = new Thread(() => Handle(client));
                t.IsBackground = true;
                t.Start();
            }
        }

        static void Handle(TcpClient client)
        {
            try
            {
                using (client)
                using (var ns = client.GetStream())
                {
                    client.NoDelay = true;
                    client.ReceiveTimeout = 120000;
                    client.SendTimeout = 120000;
                    var input = new BufferedStream(ns, 65536);
                    var req = ReadRequest(input);
                    if (req == null) return;
                    try
                    {
                        Route(req, ns);
                    }
                    catch (IOException) { }
                    catch (SocketException) { }
                    catch (Exception ex)
                    {
                        try { SendJson(ns, 500, new { error = "Relay hit an error: " + ex.Message }); } catch { }
                    }
                }
            }
            catch { }
        }

        static string ReadLine(Stream s)
        {
            var buf = new List<byte>();
            while (true)
            {
                int b = s.ReadByte();
                if (b < 0) return buf.Count == 0 ? null : Encoding.UTF8.GetString(buf.ToArray());
                if (b == '\n') break;
                if (b != '\r') buf.Add((byte)b);
                if (buf.Count > 16384) throw new IOException("Header line too long");
            }
            return Encoding.UTF8.GetString(buf.ToArray());
        }

        static Request ReadRequest(Stream s)
        {
            string line = ReadLine(s);
            if (string.IsNullOrEmpty(line)) return null;
            var parts = line.Split(' ');
            if (parts.Length < 3) return null;

            var req = new Request();
            req.Method = parts[0].ToUpperInvariant();
            string target = parts[1];
            int q = target.IndexOf('?');
            req.Path = q >= 0 ? target.Substring(0, q) : target;
            req.Query = q >= 0 ? target.Substring(q + 1) : "";
            req.Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (int count = 0; ; count++)
            {
                if (count > 100) return null;
                string h = ReadLine(s);
                if (h == null) return null;
                if (h.Length == 0) break;
                int c = h.IndexOf(':');
                if (c > 0) req.Headers[h.Substring(0, c).Trim()] = h.Substring(c + 1).Trim();
            }

            string cl;
            if (req.Headers.TryGetValue("Content-Length", out cl))
            {
                long len;
                if (long.TryParse(cl, out len) && len >= 0) { req.ContentLength = len; req.HasContentLength = true; }
            }
            req.Body = s;
            return req;
        }

        static string Header(Request req, string name)
        {
            string v;
            return req.Headers.TryGetValue(name, out v) ? v : null;
        }

        static string QueryValue(Request req, string key)
        {
            foreach (var pair in req.Query.Split('&'))
            {
                int eq = pair.IndexOf('=');
                if (eq > 0 && pair.Substring(0, eq) == key) return Uri.UnescapeDataString(pair.Substring(eq + 1));
            }
            return null;
        }

        static string Reason(int code)
        {
            switch (code)
            {
                case 200: return "OK";
                case 204: return "No Content";
                case 400: return "Bad Request";
                case 401: return "Unauthorized";
                case 404: return "Not Found";
                case 409: return "Conflict";
                case 411: return "Length Required";
                case 500: return "Internal Server Error";
                case 507: return "Insufficient Storage";
                default: return "OK";
            }
        }

        static void WriteHead(Stream ns, int code, string type, long length, string[] extra)
        {
            var sb = new StringBuilder();
            sb.Append("HTTP/1.1 ").Append(code).Append(' ').Append(Reason(code)).Append("\r\n");
            if (type != null) sb.Append("Content-Type: ").Append(type).Append("\r\n");
            sb.Append("Content-Length: ").Append(length).Append("\r\n");
            sb.Append("Cache-Control: no-store\r\n");
            sb.Append("X-Content-Type-Options: nosniff\r\n");
            sb.Append("Connection: close\r\n");
            if (extra != null) foreach (var h in extra) sb.Append(h).Append("\r\n");
            sb.Append("\r\n");
            var bytes = Encoding.UTF8.GetBytes(sb.ToString());
            ns.Write(bytes, 0, bytes.Length);
        }

        static void Send(Stream ns, int code, string type, byte[] body, string[] extra)
        {
            WriteHead(ns, code, type, body.Length, extra);
            ns.Write(body, 0, body.Length);
            ns.Flush();
        }

        static void SendJson(Stream ns, int code, object obj, params string[] extra)
        {
            Send(ns, code, "application/json; charset=utf-8", Encoding.UTF8.GetBytes(NewJson().Serialize(obj)), extra);
        }

        static Dictionary<string, object> ReadJson(Request req)
        {
            string ct = Header(req, "Content-Type") ?? "";
            if (!ct.StartsWith("application/json", StringComparison.OrdinalIgnoreCase)) return null;
            if (!req.HasContentLength || req.ContentLength > 65536) return null;
            var buf = new byte[req.ContentLength];
            int off = 0;
            while (off < buf.Length)
            {
                int n = req.Body.Read(buf, off, buf.Length - off);
                if (n <= 0) return null;
                off += n;
            }
            try { return NewJson().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(buf)); }
            catch { return null; }
        }

        static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v != null ? v.ToString() : "";
        }

        // ---------------- routes ----------------

        static void Route(Request req, Stream ns)
        {
            string p = req.Path;
            string m = req.Method;

            if (m == "GET" && (p == "/" || p == "/index.html"))
            {
                Send(ns, 200, "text/html; charset=utf-8", PageBytes, null);
                return;
            }
            if (m == "GET" && p == "/favicon.ico") { Send(ns, 204, null, new byte[0], null); return; }
            if (m == "POST" && p == "/api/signup") { SignUp(req, ns); return; }
            if (m == "POST" && p == "/api/login") { SignIn(req, ns); return; }
            if (m == "POST" && p == "/api/logout") { SignOut(req, ns); return; }

            string uid = CurrentUser(req);
            if (uid == null) { SendJson(ns, 401, new { error = "Sign in first." }); return; }

            if (m == "GET" && p == "/api/me")
            {
                string email;
                lock (Gate) email = db.Users.First(u => u.Id == uid).Email;
                SendJson(ns, 200, new { email = email });
                return;
            }
            if (m == "GET" && p == "/api/info")
            {
                SendJson(ns, 200, new { addresses = Addresses().Select(a => "http://" + a + ":" + Port).ToArray(), free = FreeSpace() });
                return;
            }
            if (m == "GET" && p == "/api/files") { ListFiles(req, ns, uid); return; }
            if (m == "POST" && p == "/api/upload") { Upload(req, ns, uid); return; }

            if (p.StartsWith("/api/files/"))
            {
                string rest = p.Substring("/api/files/".Length);
                if (m == "GET" && rest.EndsWith("/download"))
                {
                    Download(ns, uid, rest.Substring(0, rest.Length - "/download".Length));
                    return;
                }
                if (m == "DELETE") { DeleteFile(ns, uid, rest); return; }
            }

            SendJson(ns, 404, new { error = "Not found." });
        }

        static string SessionCookie(string token)
        {
            return "Set-Cookie: " + CookieName + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000";
        }

        static string SessionToken(Request req)
        {
            string c = Header(req, "Cookie");
            if (c == null) return null;
            foreach (var part in c.Split(';'))
            {
                string kv = part.Trim();
                if (kv.StartsWith(CookieName + "=")) return kv.Substring(CookieName.Length + 1);
            }
            return null;
        }

        static string CurrentUser(Request req)
        {
            string token = SessionToken(req);
            if (token == null) return null;
            lock (Gate)
            {
                var s = db.Sessions.FirstOrDefault(x => x.Token == token);
                return s == null ? null : s.UserId;
            }
        }

        static string NewSession(string uid)
        {
            string token = RandomHex(32);
            db.Sessions.Add(new SessionRec { Token = token, UserId = uid, Created = Now() });
            return token;
        }

        static bool ValidEmail(string email)
        {
            return email.Length <= 254 && Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        static void SignUp(Request req, Stream ns)
        {
            var d = ReadJson(req);
            if (d == null) { SendJson(ns, 400, new { error = "Bad request." }); return; }
            string email = Str(d, "email").Trim().ToLowerInvariant();
            string pw = Str(d, "password");
            if (!ValidEmail(email)) { SendJson(ns, 400, new { error = "Enter a valid email address." }); return; }
            if (pw.Length < 8) { SendJson(ns, 400, new { error = "Use a password with at least 8 characters." }); return; }

            string salt = RandomHex(16);
            string hash = HashPassword(pw, salt);
            string token = null;
            lock (Gate)
            {
                if (!db.Users.Any(u => u.Email == email))
                {
                    var user = new UserRec { Id = RandomHex(16), Email = email, Salt = salt, Hash = hash, Created = Now() };
                    db.Users.Add(user);
                    token = NewSession(user.Id);
                    SaveDb();
                }
            }
            if (token == null) { SendJson(ns, 409, new { error = "An account with this email already exists. Sign in instead." }); return; }
            SendJson(ns, 200, new { email = email }, SessionCookie(token));
        }

        static void SignIn(Request req, Stream ns)
        {
            var d = ReadJson(req);
            if (d == null) { SendJson(ns, 400, new { error = "Bad request." }); return; }
            string email = Str(d, "email").Trim().ToLowerInvariant();
            string pw = Str(d, "password");

            UserRec user;
            lock (Gate) user = db.Users.FirstOrDefault(u => u.Email == email);
            bool ok = user != null && SlowEquals(HashPassword(pw, user.Salt), user.Hash);
            if (!ok)
            {
                Thread.Sleep(700);
                SendJson(ns, 401, new { error = "Email or password is incorrect." });
                return;
            }
            string token;
            lock (Gate) { token = NewSession(user.Id); SaveDb(); }
            SendJson(ns, 200, new { email = user.Email }, SessionCookie(token));
        }

        static void SignOut(Request req, Stream ns)
        {
            string token = SessionToken(req);
            if (token != null)
            {
                lock (Gate)
                {
                    if (db.Sessions.RemoveAll(s => s.Token == token) > 0) SaveDb();
                }
            }
            SendJson(ns, 200, new { ok = true }, "Set-Cookie: " + CookieName + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
        }

        static object FileJson(FileRec f)
        {
            return new { id = f.Id, name = f.Name, size = f.Size, type = f.Type, device = f.Device, created = f.Created };
        }

        // Long-poll: waits up to 25s for a change, so other devices update almost instantly.
        static void ListFiles(Request req, Stream ns, string uid)
        {
            long after;
            if (!long.TryParse(QueryValue(req, "after") ?? "-1", out after)) after = -1;
            DateTime deadline = DateTime.UtcNow.AddSeconds(25);
            long version;
            List<FileRec> mine;
            lock (Gate)
            {
                while (VersionOf(uid) == after)
                {
                    TimeSpan left = deadline - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero) break;
                    Monitor.Wait(Gate, left);
                }
                version = VersionOf(uid);
                mine = db.Files.Where(f => f.UserId == uid).OrderByDescending(f => f.Created).ToList();
            }
            SendJson(ns, 200, new { version = version, free = FreeSpace(), files = mine.Select(f => FileJson(f)).ToArray() });
        }

        static void Upload(Request req, Stream ns, string uid)
        {
            string rawName = Header(req, "X-File-Name");
            if (rawName == null) { SendJson(ns, 400, new { error = "Missing file name." }); return; }
            if (!req.HasContentLength) { SendJson(ns, 411, new { error = "Missing file size." }); return; }

            string name;
            try { name = Uri.UnescapeDataString(rawName); } catch { name = rawName; }
            name = name.Trim();
            if (name.Length == 0) name = "untitled";
            if (name.Length > 400) name = name.Substring(name.Length - 400);

            string type = Header(req, "X-File-Type") ?? "";
            if (!TypePattern.IsMatch(type)) type = "";
            string device = Header(req, "X-Device") ?? "";
            if (device.Length > 40) device = device.Substring(0, 40);

            long len = req.ContentLength;
            long free = FreeSpace();
            if (free >= 0 && len > free - SpareBytes)
            {
                SendJson(ns, 507, new { error = "Not enough space on the Relay computer." });
                return;
            }

            string id = RandomHex(16);
            string dir = Path.Combine(FilesDir, uid);
            Directory.CreateDirectory(dir);
            string finalPath = Path.Combine(dir, id);
            string tmpPath = finalPath + ".part";

            bool complete = false;
            try
            {
                using (var fs = new FileStream(tmpPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20))
                {
                    var buf = new byte[1 << 20];
                    long left = len;
                    while (left > 0)
                    {
                        int n = req.Body.Read(buf, 0, (int)Math.Min(buf.Length, left));
                        if (n <= 0) break;
                        fs.Write(buf, 0, n);
                        left -= n;
                    }
                    complete = left == 0;
                }
                if (complete) File.Move(tmpPath, finalPath);
            }
            finally
            {
                if (!complete) TryDelete(tmpPath);
            }
            if (!complete) return; // the device disconnected or cancelled

            var rec = new FileRec { Id = id, UserId = uid, Name = name, Size = len, Type = type, Device = device, Created = Now() };
            lock (Gate)
            {
                db.Files.Add(rec);
                SaveDb();
                Bump(uid);
            }
            SendJson(ns, 200, FileJson(rec));
        }

        static void Download(Stream ns, string uid, string id)
        {
            if (!IdPattern.IsMatch(id)) { SendJson(ns, 404, new { error = "Not found." }); return; }
            FileRec f;
            lock (Gate) f = db.Files.FirstOrDefault(x => x.Id == id && x.UserId == uid);
            string path = Path.Combine(Path.Combine(FilesDir, uid), id);
            if (f == null || !File.Exists(path)) { SendJson(ns, 404, new { error = "That file is no longer on the Relay computer." }); return; }

            string baseName = f.Name.Contains("/") ? f.Name.Substring(f.Name.LastIndexOf('/') + 1) : f.Name;
            var ascii = new StringBuilder();
            foreach (char ch in baseName) ascii.Append(ch >= 32 && ch < 127 && ch != '"' && ch != '\\' ? ch : '_');

            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1 << 20))
            {
                WriteHead(ns, 200, string.IsNullOrEmpty(f.Type) ? "application/octet-stream" : f.Type, fs.Length, new[] {
                    "Content-Disposition: attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + Uri.EscapeDataString(baseName)
                });
                fs.CopyTo(ns, 1 << 20);
                ns.Flush();
            }
        }

        static void DeleteFile(Stream ns, string uid, string id)
        {
            if (!IdPattern.IsMatch(id)) { SendJson(ns, 404, new { error = "Not found." }); return; }
            FileRec f;
            lock (Gate)
            {
                f = db.Files.FirstOrDefault(x => x.Id == id && x.UserId == uid);
                if (f != null)
                {
                    db.Files.Remove(f);
                    SaveDb();
                    Bump(uid);
                }
            }
            if (f == null) { SendJson(ns, 404, new { error = "That file was already deleted." }); return; }
            TryDelete(Path.Combine(Path.Combine(FilesDir, uid), id));
            SendJson(ns, 200, new { ok = true });
        }

        // ---------------- storage ----------------

        static long VersionOf(string uid)
        {
            long v;
            return Versions.TryGetValue(uid, out v) ? v : StartVersion;
        }

        static void Bump(string uid) // call inside lock (Gate)
        {
            VersionCounter++;
            Versions[uid] = VersionCounter;
            Monitor.PulseAll(Gate);
        }

        static void LoadDb()
        {
            if (!File.Exists(DbPath)) return;
            try
            {
                var loaded = NewJson().Deserialize<Db>(File.ReadAllText(DbPath, Encoding.UTF8));
                if (loaded != null) db = loaded;
                if (db.Users == null) db.Users = new List<UserRec>();
                if (db.Sessions == null) db.Sessions = new List<SessionRec>();
                if (db.Files == null) db.Files = new List<FileRec>();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Couldn't read " + DbPath + ": " + ex.Message);
                Console.WriteLine("Fix or move that file, then start Relay again.");
                Console.ReadLine();
                Environment.Exit(1);
            }
        }

        static void SaveDb() // call inside lock (Gate)
        {
            string tmp = DbPath + ".tmp";
            File.WriteAllText(tmp, NewJson().Serialize(db), new UTF8Encoding(false));
            if (File.Exists(DbPath))
            {
                try { File.Replace(tmp, DbPath, null); }
                catch { File.Copy(tmp, DbPath, true); TryDelete(tmp); }
            }
            else
            {
                File.Move(tmp, DbPath);
            }
        }

        static void CleanPartials()
        {
            try
            {
                foreach (var f in Directory.GetFiles(FilesDir, "*.part", SearchOption.AllDirectories)) TryDelete(f);
            }
            catch { }
        }

        static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        static long FreeSpace()
        {
            try { return new DriveInfo(Path.GetPathRoot(DataDir)).AvailableFreeSpace; }
            catch { return -1; }
        }

        // ---------------- helpers ----------------

        static List<string> Addresses()
        {
            var list = new List<string>();
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect("10.255.255.255", 1); // no data is sent; this just picks the Wi-Fi/LAN address
                    var ep = s.LocalEndPoint as IPEndPoint;
                    if (ep != null && !IPAddress.IsLoopback(ep.Address) && !ep.Address.Equals(IPAddress.Any))
                        list.Add(ep.Address.ToString());
                }
            }
            catch { }
            try
            {
                foreach (var a in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (a.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(a)) continue;
                    string s = a.ToString();
                    if (s.StartsWith("169.254.")) continue;
                    if (!list.Contains(s)) list.Add(s);
                }
            }
            catch { }
            return list;
        }

        static JavaScriptSerializer NewJson() // a fresh one per call, since the class isn't thread-safe
        {
            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        }

        static long Now()
        {
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
        }

        static string RandomHex(int bytes)
        {
            var b = new byte[bytes];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(b);
            return ToHex(b);
        }

        static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        static byte[] FromHex(string hex)
        {
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        static string HashPassword(string pw, string saltHex)
        {
            using (var kdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(pw), FromHex(saltHex), PasswordIterations))
                return ToHex(kdf.GetBytes(32));
        }

        static bool SlowEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
