﻿using AuthenticodeExaminer;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Drawing;
using Pastel;

namespace SMT.helpers
{
    public class SMTHelper
    {
        #region Variables

        // Thanks to https://stackoverflow.com/users/754438/renatas-mp
        [DllImport("user32.dll")] public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);
        [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("kernel32.dll", ExactSpelling = true)] public static extern IntPtr GetConsoleWindow();

        public static List<string> Csrss_files = new List<string>();
        public const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;
        public static Process pr = new Process();
        public static Random r = new Random();
        public static string[] prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch");
        public static string strings2, unprotect;
        public static int SMTDir = r.Next(1000, 9999);
        public static bool lsass = false, DPS = false, DNS = false, Javaw = false, DiagTrack = false;
        #endregion

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static void Wait()
        {
            Thread.Sleep(5000);
        }

        public static string GetPID(string process)
        {
            string finalpid = "";

            pr.StartInfo.FileName = "sc.exe";
            pr.StartInfo.Arguments = "queryex \"" + process + "\"";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            pr.Start();
            pr.WaitForExit();
            string output = pr.StandardOutput.ReadToEnd();
            pr.Close();

            if (output.IndexOf(process) != -1)
            {
                bool getPid = false;
                string[] words = output.Split(':');
                foreach (string word in words)
                {
                    if (word.IndexOf("PID") != -1 && getPid == false)
                    {
                        getPid = true;
                    }
                    else if (getPid)
                    {
                        string[] pid = word.Split('\r');
                        finalpid += pid[0];
                    }
                }
            }
            else
            {
                finalpid = "Unexpected error";
            }

            return finalpid;
        }

        public static void ExtractFile()
        {
            if (Directory.Exists(@"C:\ProgramData"))
            {
                Directory.CreateDirectory($@"C:\ProgramData\SMT-{SMTDir}");

                strings2 = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "strings2.exe");
                unprotect = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "unprotect.exe");

                File.WriteAllBytes(strings2, Properties.Resources.strings2);
                File.WriteAllBytes(unprotect, Properties.Resources.unprotecting_process);
            }
            else
            {
                SMT.RESULTS.Errors.Add(@"C:\ProgramData directory doesn't exist, please create it and restart smt");
                ConsoleHelper.WriteLine(@"C:\ProgramData directory doesn't exist, please create it and restart smt", ConsoleColor.Yellow);
                Console.ReadLine();
            }
        }

        public static bool ContainsUnicodeCharacter(string input)
        {
            ///Original post: https://stackoverflow.com/questions/4459571/how-to-recognize-if-a-string-contains-unicode-chars

            const int MaxAnsiCode = 255;

            return input.Any(c => c > MaxAnsiCode);
        }

        public static void SaveFile(string arg)
        {
            ProcessStartInfo scan = new ProcessStartInfo()
            {
                FileName = @"CMD.exe",
                Arguments = $@"/C {arg}",
                UseShellExecute = false,
                RedirectStandardOutput = true,

            };

            Process check = Process.Start(scan);
            check.WaitForExit();

            if (check.ExitCode != 0)
            {
                SMT.RESULTS.Errors.Add("AntiSS Tool detected, please check programs in background, some checks will be skipped");
                Console.WriteLine("There is a problem with some checks, please disable antivirus and restart SMT");
                Console.ReadLine();
            }

            check.Close();
        }

        public static string GetCorrectMCProcess()
        {
            string process = "";

            if (Process.GetProcessesByName("javaw").Length > 0 && Process.GetProcessesByName("java").Length > 0)
            {
                using (Process Javaw = Process.GetProcessesByName("javaw")[0])
                {
                    using (Process Java = Process.GetProcessesByName("java")[0])
                    {
                        if (Javaw.WorkingSet64 > Java.WorkingSet64)
                        {
                            process += "javaw";
                        }
                        else
                        {
                            process += "java";
                        }
                    }
                }
            }
            else if (Process.GetProcessesByName("javaw").Length > 0 && Process.GetProcessesByName("java").Length == 0)
            {
                process += "javaw";
            }
            else if (Process.GetProcessesByName("java").Length > 0 && Process.GetProcessesByName("javaw").Length == 0)
            {
                process += "java";
            }
            else if (Process.GetProcessesByName("javaw").Length == 0
                && Process.GetProcessesByName("java").Length == 0
                && Process.GetProcessesByName("launcher").Length > 0)
            {
                process += "launcher";
            }
            return process;
        }

        public static string MinecraftMainProcess = GetCorrectMCProcess();

        public static bool isCorrectMC()
        {
            bool isMc = false;

            if (Process.GetProcessesByName(GetCorrectMCProcess()).Length > 0)
            {
                isMc = true;
            }

            return isMc;
        }

        public static string CheaterJoke()
        {
            string Joke = "";
            int counter = 0;
            Random random = new Random();
            int FraseRandom = random.Next(1, 40);

            WebClient client = new WebClient();
            using (Stream stream = client.OpenRead("https://pastebin.com/raw/FP7qvFYL"))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        ++counter;

                        if (FraseRandom == counter)
                        {
                            Joke += line;
                        }
                    }
                }
            }

            return Joke;
        }

        public static string GetSign(string file)
        {
            string signature = "";

            FileInspector extractor = new FileInspector(file);
            SignatureCheckResult validationResult = extractor.Validate();

            switch (validationResult)
            {
                case SignatureCheckResult.Valid:
                    signature = "Signed";
                    break;
                case SignatureCheckResult.NoSignature:
                    signature = "Unsigned";
                    break;
                case SignatureCheckResult.BadDigest:
                    signature = "Fake";
                    break;
                default:
                    break;
            }

            return signature;
        }

        public static void UnProtectProcess(int PID)
        {
            Console.OutputEncoding = Encoding.UTF8;

            pr.StartInfo.FileName = $@"C:\ProgramData\SMT-{SMTDir}\unprotect.exe";
            pr.StartInfo.Arguments = $"/d {PID}";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.Start();
            pr.WaitForExit();
        }

        public static string SHA256CheckSum(string filePath)
        {
            using (SHA256 SHA256 = SHA256Managed.Create())
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    return Convert.ToBase64String(SHA256.ComputeHash(fileStream));
                }
            }
        }

        public static bool IsExternalClient(string SuspyFile)
        {
            bool isClient = false;

            if (File.ReadLines(SuspyFile).First()[0] == 'M'
                            && File.ReadLines(SuspyFile).First()[1] == 'Z'
                            && File.ReadLines(SuspyFile).First().Contains("This program cannot be run in DOS mode")
                            && File.ReadAllText(SuspyFile).Contains("__std_type_info_destroy_list")
                            && File.ReadAllText(SuspyFile).Contains("__C_specific_handler")
                            && File.ReadAllText(SuspyFile).Contains("memset")
                            && (File.ReadAllText(SuspyFile).Contains("ReadProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("WriteProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("GetKeyState")
                            || File.ReadAllText(SuspyFile).Contains("GetAsyncKeyState")
                            || File.ReadAllText(SuspyFile).Contains("mouse_event")))
            {
                isClient = true;
            }

            return isClient;
        }

        public static NtFile OpenReparseDirectory(string volume)
        {
            return NtFile.Open($@"\??\{volume}\$Extend\$Reparse:$R:$INDEX_ALLOCATION", null, FileAccessRights.GenericRead | FileAccessRights.Synchronize,
                FileShareMode.Read, FileOpenOptions.OpenForBackupIntent | FileOpenOptions.SynchronousIoNonAlert);
        }

        public static string GetDirectoryFromID(string journal_line, string filemissed)
        {
            string directory = "";
            string directory2 = "";

            if (journal_line.ToUpper().Contains(filemissed.ToUpper()))
            {
                Regex due_id = new Regex("\",00.*?,.*?0x");
                Regex virgole_e_apostrofo = new Regex("\",");
                Regex virgola = new Regex(",");
                Regex apostrofo = new Regex("\"");
                Regex space = new Regex(".*? .*? ");
                Regex spazio = new Regex(" ");
                Regex first_ID = new Regex(".*? ");
                Regex second_ID = new Regex(" .*? ");

                Match mch = due_id.Match(journal_line);
                string dino = virgole_e_apostrofo.Replace(mch.Value, "");
                dino = virgola.Replace(dino, " ");
                Match mimmo = space.Match(dino);

                Match primo = first_ID.Match(mimmo.Value);

                Match secondo = second_ID.Match(mimmo.Value);

                if (mimmo.Success
                && primo.Success
                && secondo.Success)
                {
                    string fringuello = spazio.Replace(primo.Value, "");
                    string fringuello2 = spazio.Replace(secondo.Value, "");
                    long dino_pino = Convert.ToInt64(fringuello, 16);
                    long pino_dino = Convert.ToInt64(fringuello2, 16);

                    try
                    {
                        using (NtFile file = NtFile.OpenFileById(OpenReparseDirectory("C:"), dino_pino, FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
                        FileShareMode.None, FileOpenOptions.DirectoryFile | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent))
                        {
                            string filename = file.GetWin32PathName(NtApiDotNet.Win32.Win32PathNameFlags.None, false).GetResultOrDefault(primo.Value);
                            directory = filename;
                        }
                    }
                    catch (Exception)
                    {

                    }

                    try
                    {
                        using (NtFile file = NtFile.OpenFileById(OpenReparseDirectory("C:"), pino_dino, FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
                        FileShareMode.None, FileOpenOptions.DirectoryFile | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent))
                        {
                            string filename = file.GetWin32PathName(NtApiDotNet.Win32.Win32PathNameFlags.None, false).GetResultOrDefault(secondo.Value);
                            directory2 = filename;
                        }
                    }
                    catch (Exception)
                    {
                    }
                }

                if (directory2.Length > directory.Length)
                {
                    string sergio = virgola.Replace(filemissed, "");
                    sergio = apostrofo.Replace(sergio, "");
                    directory = directory2 + "\\" + sergio;
                }
                else
                {
                    string sergio = virgola.Replace(filemissed, "");
                    sergio = apostrofo.Replace(sergio, "");
                    directory = directory + "\\" + sergio;
                }
            }
            return directory;
        }

        public static string Detection(string detection_type, string detection, string time)
        {
            string detection_return = "";

            switch (detection_type)
            {
                case "Deleted":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Bypass method":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Moved/Renamed":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(235, 149, 50))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Suspicious File":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Fake digital signature":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(254, 250, 212))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Out of Instance":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "In Instance":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(0, 230, 64))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Wmic Method":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(140, 20, 252))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
            }

            return detection_return;
        }

        public static void SaveAllFiles()
        {
            Header header = new Header();
            header.Stages(0, CheaterJoke());

            //csrss
            try
            {
                if (Process.GetProcessesByName("csrss")[0].PagedMemorySize64 > Process.GetProcessesByName("csrss")[1].PagedMemorySize64)
                {
                    UnProtectProcess(Process.GetProcessesByName("csrss")[0].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("csrss")[0].Id} > C:\ProgramData\SMT-{SMTDir}\csrss.txt");
                }
                else
                {
                    UnProtectProcess(Process.GetProcessesByName("csrss")[1].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("csrss")[1].Id} > C:\ProgramData\SMT-{SMTDir}\csrss.txt");
                }
            }
            catch
            {

            }

            //pcasvc (non scanna più)
            try
            {
                if (GetPID("pcasvc") != " 0 ")
                {

                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (PcaSvc process missed)");
                }
            }
            catch { }

            //DPS
            try
            {
                if (GetPID("DPS") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DPS")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
                    DPS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DPS process missed)");
                }
            }
            catch { }

            //lsass
            try
            {
                if (Process.GetProcessesByName("lsass")[0].Id > 0)
                {
                    UnProtectProcess(Convert.ToInt32(Process.GetProcessesByName("lsass")[0].Id));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {Process.GetProcessesByName("lsass")[0].Id} > C:\ProgramData\SMT-{SMTDir}\Browser.txt");
                    lsass = true;
                }
            }
            catch { }

            //DNS
            try
            {
                if (GetPID("dnscache") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("dnscache")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {GetPID("dnscache")} > C:\ProgramData\SMT-{SMTDir}\dns.txt");
                    DNS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DNScache process missed)");
                }
            }
            catch { }

            //DiagTrack
            try
            {
                if (GetPID("DiagTrack") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DiagTrack")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");

                    string[] DiagTrack_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\utcsvc.txt");
                    if (DiagTrack_lines.Contains("cmd.exe")
                        && DiagTrack_lines.Contains("del")
                        && DiagTrack_lines.Contains(".pf"))
                    {
                        SMT.RESULTS.string_scan.Add("Found generic prefetch's file(s) Self-destruct");
                    }
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
                }
            }
            catch { }
        }
    }
}
