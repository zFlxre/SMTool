using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SMT.helpers
{

    //[StructLayout(LayoutKind.Sequential)]
    //public struct FileReparseTagInformation
    //{
    //    public long FileReferenceNumber;
    //    public ReparseTag Tag;
    //}

    //public struct FileData
    //{
    //    public string FileName;
    //    public ReparseBuffer Reparse;
    //}
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
        public static Process[] prlist = Process.GetProcesses();
        public static ProcessStartInfo startInfo = new ProcessStartInfo();
        public static Random r = new Random();
        public static string[] prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch");
        public static string[] MinecraftProcesses = new string[] { "javaw", "launcher", "Lunar Client" };
        public static string str, result, result2, sigcheck, strings2, unprotect;
        public static int SMTDir = r.Next(1000, 9999);
        public static bool DPS = false, DNS = false, Javaw = false, DiagTrack = false;
        public static string Csrss_Dir = "";

        public static Regex virgole = new Regex(",");
        public static Regex apostrofo = new Regex("\"");
        public static Regex GetID = new Regex("\",0.*?,0x");
        public static Regex leva_primevirgole = new Regex("\",.*?,");
        public static Regex replace0x = new Regex(",0x");
        public static Regex getaddress = new Regex("0.*?$");
        public static Regex CinuqueVirgole = new Regex(@",.*?\|.*?,");
        public static Regex TraApostrofo = new Regex("\".*?\"");
        #endregion

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static void Exit()
        {
            Thread.Sleep(5000);
        }

        public static DateTime GetFileDateTime(string line)
        {
            string data_fiunzoa;

            data_fiunzoa = CinuqueVirgole.Replace(line, "");
            Match GetData = TraApostrofo.Match(data_fiunzoa);
            data_fiunzoa = virgole.Replace(GetData.Value, "");
            data_fiunzoa = apostrofo.Replace(data_fiunzoa, "");

            return DateTime.Parse(data_fiunzoa);
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

                sigcheck = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "sigcheck.exe");
                strings2 = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "strings2.exe");
                unprotect = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "unprotect.exe");

                File.WriteAllBytes(sigcheck, Properties.Resources.sigcheck64);
                File.WriteAllBytes(strings2, Properties.Resources.strings2);
                File.WriteAllBytes(unprotect, Properties.Resources.unprotecting_process);
            }
            else
            {
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
            else if(Process.GetProcessesByName("javaw").Length == 0 
                && Process.GetProcessesByName("java").Length == 0
                && Process.GetProcessesByName("launcher").Length > 0)
            {
                process += "launcher";
            }
            return process;
        }

        public static string MinecraftMainProcess = GetCorrectMCProcess();

        public static string StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes.ToString();
        }

        public static bool isCorrectMC()
        {
            bool isMc = false;

            if (Process.GetProcessesByName(GetCorrectMCProcess()).Length > 0)
            {
                isMc = true;
            }

            return isMc;
        }

        public static void Loading()
        {
            while (true)
            {
            }
        }

        public static string CheaterJoke()
        {
            string Joke = "";
            int counter = 0;
            Random random = new Random();
            int FraseRandom = random.Next(1, 22);

            WebClient client = new WebClient();
            using (Stream stream = client.OpenRead("https://pastebin.com/raw/FP7qvFYL"))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        counter++;
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

            Console.OutputEncoding = Encoding.UTF8;

            pr.StartInfo.FileName = $@"C:\ProgramData\SMT-{SMTDir}\sigcheck.exe";
            pr.StartInfo.Arguments = "/C -a -accepteula \"" + file + "\"";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.Start();
            pr.WaitForExit();
            signature += pr.StandardOutput.ReadToEnd();
            pr.Close();

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

        public static void GetFileBytes(string file)
        {
            byte[] file_lines = File.ReadAllBytes(file);

            WebClient client = new WebClient();
            string cheat, client_str;

            using (Stream stream = client.OpenRead(@"https://pastebin.com/raw/byHrvMm9"))
            {
                using (BufferedStream bs = new BufferedStream(stream))
                {
                    using (StreamReader streamReader = new StreamReader(bs))
                    {
                        string streamReader_line;

                        while ((streamReader_line = streamReader.ReadLine()) != null)
                        {
                            client_str = streamReader_line.Split(new char[]
                            {
                                    '§'
                            })[0];
                            cheat = streamReader_line.Split(new char[]
                            {
                                   '§'
                            })[1];

                            if (file_lines.ToString().Contains(StringToByteArray(client_str)))
                            {
                                SMT.RESULTS.string_scan.Add("Out of Instance: " + cheat + " " + file);
                            }
                        }
                    }
                }
            }
        }

        public static bool IsExternalClient(string SuspyFile)
        {
            bool isClient = false;

            if (File.ReadLines(SuspyFile).First()[0] == 'M'
                            && File.ReadLines(SuspyFile).First()[1] == 'Z'
                            && File.ReadLines(SuspyFile).First() == "This program cannot be run in DOS mode"
                            && File.ReadAllText(SuspyFile).Contains("__std_type_info_destroy_list")
                            && File.ReadAllText(SuspyFile).Contains("__C_specific_handler")
                            && File.ReadAllText(SuspyFile).Contains("memset")
                            && (File.ReadAllText(SuspyFile).Contains("ReadProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("WriteProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("AllocConsole")
                            || File.ReadAllText(SuspyFile).Contains("GetKeyState")
                            || File.ReadAllText(SuspyFile).Contains("GetAsyncKeyState")))
            {
                isClient = true;
            }

            return isClient;
        }

        public static void SaveAllFiles()
        {
            Header header = new Header();
            header.Stages(0, CheaterJoke());

            //csrss
            try
            {
                UnProtectProcess(Process.GetProcessesByName("csrss")[0].Id);
                SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -a -pid {Process.GetProcessesByName("csrss")[0].Id} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt");
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

            //DPS (Specific)
            try
            {
                if (GetPID("DPS") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DPS")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {SMTHelper.GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
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
                if (GetPID("lsass") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("lsass")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -a -pid {SMTHelper.GetPID("lsass")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
                    DNS = true;
                }
            }
            catch { }

            //DiagTrack
            //try
            //{
            //    if (GetPID("DiagTrack") != " 0 ")
            //    {
            //        UnProtectProcess(Convert.ToInt32(GetPID("DiagTrack")));
            //        SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {SMTHelper.GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");
            //        DiagTrack = true;
            //    }
            //    else
            //    {
            //        SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
            //    }
            //}
            //catch { }

        }
    }
}
