using Microsoft.Win32;
using SMT.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SMT.scanners
{
    public class Checks
    {
        public Header header = new Header();

        public static string[] MinecraftProcesses = new string[] { "javaw", "launcher", "AlphaAntiLeak" };
        public static bool can_scan = true;

        #region EventLog(s) Global Variable(s)
        public EventLog GetSecurity_log = new EventLog("Security");
        public EventLog GetSystem_log = new EventLog("System");
        public EventLog GetApplication_log = new EventLog("Application");
        #endregion

        #region Global List(s)
        public List<string> possible_replaces { get; set; } = new List<string>();
        public List<string> suspy_files { get; set; } = new List<string>();
        public string injected_dll { get; set; } = string.Empty; // only date
        public List<string> generic_jnas { get; set; } = new List<string>();
        public List<string> event_viewer_entries { get; set; } = new List<string>();


        #endregion

        #region Global Regex Strings
        private readonly Regex GetFullFilePath = new Regex(@"[A-Z]:\\.*?$");
        #endregion

        public void HeuristicCsrssCheck()
        {
            string CsrssFile_line;
            CsrssFile_line = "";

            using (StreamReader Read_CsrssFile = new StreamReader($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt"))
            {
                while ((CsrssFile_line = Read_CsrssFile.ReadLine()) != null)
                {
                    Match FullFilePath_Match = GetFullFilePath.Match(CsrssFile_line.ToUpper());

                    //DLL

                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) == ".DLL"
                        && File.Exists(FullFilePath_Match.Value)
                        && SMTHelper.IsExternalClient(FullFilePath_Match.Value))
                    {
                        SMT.RESULTS.suspy_files.Add("Injected DLL found: " + FullFilePath_Match.Value);
                    }

                    #region ByteArray Check
                    //if (FullFilePath_Match.Value.Length > 0
                    //    && !Directory.Exists(FullFilePath_Match.Value)
                    //    && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                    //    && File.Exists(FullFilePath_Match.Value))
                    //{
                    //    Action GetFile_Bytes = () => SMTHelper.GetFileBytes(FullFilePath_Match.Value); ;
                    //    SMT.runCheckAsync(GetFile_Bytes);
                    //}
                    #endregion

                    //File Unsigned

                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned"))
                    {
                        SMT.RESULTS.suspy_files.Add("File unsigned: " + FullFilePath_Match.Value);
                    }

                    //Get Vape Lite and Yukio

                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && (SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Manthe Industries")
                        || SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Mynt SASU")))
                    {
                        SMT.RESULTS.suspy_files.Add("File with Generic Client's digital sign: " + FullFilePath_Match.Value);
                    }

                    //Fake Extension(s)

                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) != ".CONFIG"
                        && Path.GetExtension(FullFilePath_Match.Value) != ".CPL"
                        && Path.GetExtension(FullFilePath_Match.Value) != ".NODE"
                        && Path.GetExtension(FullFilePath_Match.Value) != ".MANIFEST"
                        && Path.GetExtension(FullFilePath_Match.Value) != ".DLL"
                        && Path.GetExtension(FullFilePath_Match.Value) != ".EXE")
                    {
                        if (File.Exists(FullFilePath_Match.Value))
                        {
                            if (SMTHelper.IsExternalClient(FullFilePath_Match.Value))
                            {
                                SMT.RESULTS.suspy_files.Add($"External client found: {FullFilePath_Match.Value}");
                            }
                        }
                        else
                        {
                            SMT.RESULTS.suspy_files.Add($"File doesn't exist | File: {FullFilePath_Match.Value}");
                        }
                    }
                }
            }

            SMT.RESULTS.suspy_files.Sort();
        } //Refractored

        public Process pr = new Process();

        public void isValueJournalDefault()
        {
            pr.StartInfo.FileName = "CMD.exe";
            pr.StartInfo.Arguments = "fsutil usn queryjournal C:";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            pr.Start();
            pr.WaitForExit();
            string output = pr.StandardOutput.ReadToEnd();
            pr.Close();

            if (!output.Contains("0x7fffffffffff0000")
                && !output.Contains("0x0000000002000000 (32,0 MB)")
                && !output.Contains("0x0000000000800000")
                && !output.Contains("0x0000000000000000"))
            {
                SMT.RESULTS.bypass_methods.Add("USN Journal's default values was modified");
            }
        }

        public void StringScannerSystem(string link, char separator, string result)
        {
            //StringScanner system by GabTeix (https://github.com/GabTeix) (project removed)

            string[] file_lines = File.ReadAllLines(result);

            WebClient client = new WebClient();
            string cheat, client_str;

            List<string> clientsdetected = new List<string>();

            bool can_scan = true;
            ManagementClass mngmtClass = new ManagementClass("Win32_Process");

            foreach (ManagementObject o in mngmtClass.GetInstances())
            {
                if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0
                    && !Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].MainWindowTitle.ToString().Contains("Lunar")
                    && !Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].MainWindowTitle.ToString().Contains("Badlion"))
                {
                    if (o["Name"].Equals(SMTHelper.MinecraftMainProcess))
                    {
                        if (o["CommandLine"].ToString().Contains(@"11.15.1.1722"))
                        {
                            can_scan = false;
                            break;
                        }
                    }
                }
            }

            using (Stream stream = client.OpenRead(link))
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
                                    separator
                            })[0];
                            cheat = streamReader_line.Split(new char[]
                            {
                                   separator
                            })[1];

                            if ((link == "https://pastebin.com/raw/YtQUM50C"
                                || link == "https://pastebin.com/raw/bBtUqdJN"
                                || link == "https://pastebin.com/raw/byHrvMm9")
                                && file_lines.Contains(client_str))
                            {
                                SMT.RESULTS.string_scan.Add("Out of instance: " + cheat);
                            }
                            else if (link == "https://pastebin.com/raw/zh0UaeG4"
                                && file_lines.Contains(client_str) && !cheat.Contains("Found Generic")
                                && (can_scan == false || can_scan))
                            {
                                SMT.RESULTS.string_scan.Add("In instance: " + cheat);
                            }
                        }
                    }
                }
            }

            file_lines = new string[] { };

            for (int j = 0; j < clientsdetected.Count; j++)
            {
                SMT.RESULTS.string_scan.Add(clientsdetected[j]);
            }
        } //Refractored

        public void StringScan()
        {
            if (SMTHelper.DPS)
            {
                StringScannerSystem("https://pastebin.com/raw/YtQUM50C", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
            }

            if (SMTHelper.DNS)
            {
                StringScannerSystem("https://pastebin.com/raw/BJ388A4H", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
            }

            if (SMTHelper.Javaw)
            {
                StringScannerSystem("https://pastebin.com/raw/zh0UaeG4", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
            }

            if (SMTHelper.DiagTrack)
            {
                string file_lines = File.ReadAllText($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");

                if ((file_lines.Contains("cmd.exe") && file_lines.Contains("del")) || file_lines.Contains("/c ping 1.1.1.1 -n 1 -w 3000 > nul & del /f /q"))
                {
                    SMT.RESULTS.string_scan.Add($"Out of instance: Generic Command Line self-destruct Found!");
                }
            }

        } //Refractored

        public void SaveJavaw()
        {
            if (can_scan && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
            {
                SMTHelper.UnProtectProcess(Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id);
                SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -a -pid {Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
                SMTHelper.Javaw = true;
            }
        }

        public void SaveJournal()
        {
            if (can_scan && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
            {
                SMTHelper.SaveFile($"fsutil usn readjournal c: csv | findstr /i /C:\"" + "0x80000200" + "\"" + " /C:\"" + "0x00001000" + "\"" + " /C:\"" + "0x80200120" + "\"" + " /C:\"" + "0x00000800" + "\"" + $@" > C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
                SMTHelper.Javaw = true;
            }
        }

        public void SaveDiagTrack()
        {
            try
            {
                if (SMTHelper.GetPID("DiagTrack") != " 0 ")
                {
                    SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {SMTHelper.GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");
                    SMTHelper.DiagTrack = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
                }
            }
            catch { }
        }

        public void SavePcaSvc()
        {
            try
            {
                if (SMTHelper.GetPID("pcasvc") != " 0 ")
                {

                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (PcaSvc process missed)");
                }
            }
            catch { }
        }

        public void SaveDNS()
        {
            try
            {
                if (SMTHelper.GetPID("Dnscache") != " 0 ")
                {
                    SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -pid {SMTHelper.GetPID("Dnscache")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
                    SMTHelper.DNS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DNS process missed)");
                }
            }
            catch { }
        }

        public void SaveDPS()
        {
            try
            {
                if (SMTHelper.GetPID("DPS") != " 0 ")
                {
                    SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {SMTHelper.GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
                    SMTHelper.DPS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DPS process missed)");
                }
            }
            catch { }
        }

        public void EventVwrCheck()
        {
            string bytes = "";

            string LogSource = "Microsoft-Windows-User Device Registration/Admin";
            string sQuery = "*[System/EventID=360]";

            string StorageSpaces = "Microsoft-Windows-StorageSpaces-Driver/Operational";
            string bQuery = "*[System/EventID=207]";

            foreach (EventLogEntry eventlogentry in GetSecurity_log.Entries)
            {
                if (eventlogentry.InstanceId == 1102 && SMTHelper.PC_StartTime() < eventlogentry.TimeGenerated)
                {
                    SMT.RESULTS.event_viewer_entries.Add($"Security Event viewer logs deleted today");
                }
            }

            EventRecord entry;
            string logPath = @"C:\Windows\System32\winevt\Logs\Security.evtx";
            EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);

            while ((entry = logReader.ReadEvent()) != null)
            {
                if (entry.Id != 4616)
                {
                    continue;
                }

                if (entry.TimeCreated <= SMTHelper.PC_StartTime())
                {
                    continue;
                }

                IList<EventProperty> properties = entry.Properties;
                DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                {
                    SMT.RESULTS.event_viewer_entries.Add($"System time change was detected: Old -> {previousTime} New -> {newTime}");
                }
            }

            foreach (EventLogEntry Security in GetSystem_log.Entries)
            {
                if (Security.InstanceId == 104 && SMTHelper.PC_StartTime() <= Security.TimeGenerated)
                {
                    SMT.RESULTS.event_viewer_entries.Add($"'System' Event viewer logs deleted today");
                }

#pragma warning disable CS0618 // Il tipo o il membro è obsoleto
                if (Security.EventID == 7031 && SMTHelper.PC_StartTime() <= Security.TimeGenerated)
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                {
                    foreach (byte single_bytes in Security.Data)
                    {
                        bytes += single_bytes;
                    }
                }
            }

            foreach (EventLogEntry Application_log in GetApplication_log.Entries)
            {
#pragma warning disable CS0618 // Il tipo o il membro è obsoleto
                if (Application_log.EventID == 3079 && SMTHelper.PC_StartTime() <= Application_log.TimeGenerated)
                {
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                    SMT.RESULTS.event_viewer_entries.Add("USN Journal was deleted || Date: " + Application_log.TimeGenerated);
                }
            }

            //Explorer

            EventLogQuery elQuery = new EventLogQuery(LogSource, PathType.LogName, sQuery);
            using (EventLogReader elReader = new EventLogReader(elQuery))
            {
                for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                {
                    if (dodo.TimeCreated >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add($"Explorer restarted after Minecraft || Date: {dodo.TimeCreated}");
                    }
                }
            }

            //USB

            EventLogQuery rQuery = new EventLogQuery(StorageSpaces, PathType.LogName, bQuery);
            using (EventLogReader elReader = new EventLogReader(rQuery))
            {
                for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                {
                    DateTime UpdatedTime = (DateTime)dodo.TimeCreated;

                    if (dodo.TimeCreated > SMTHelper.PC_StartTime() && UpdatedTime.AddMinutes(-5) > SMTHelper.PC_StartTime())
                    {
                        SMT.RESULTS.bypass_methods.Add("USB connected at: " + dodo.TimeCreated + " please investigate");
                    }
                }
            }

            //DPS Pcasvc e DiagTrack

            if (bytes.Contains("68080083000"))
            {
                SMT.RESULTS.bypass_methods.Add("DPS was restarted");
            }
            else if (bytes.Contains("800990970830118099000"))
            {
                SMT.RESULTS.bypass_methods.Add("PcaSvc was restarted");
            }
            else if (bytes.Contains("680105097010308401140970990107000"))
            {
                SMT.RESULTS.bypass_methods.Add("DiagTrack was restarted");
            }

        } //Refractored

        public void OtherChecks()
        {
            Console.OutputEncoding = Encoding.Unicode;
            bool unicode_char = false;

            for (int j = 0; j < SMTHelper.prefetchfiles.Length; j++)
            {
                unicode_char = SMTHelper.ContainsUnicodeCharacter(SMTHelper.prefetchfiles[j]);

                if (unicode_char)
                {
                    SMT.RESULTS.bypass_methods.Add("Special char found in PREFETCH, please investigate " + SMTHelper.prefetchfiles[j] + " Used on: " + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]));
                }
                else if (SMTHelper.prefetchfiles[j].ToUpper().Contains("REGEDIT.EXE")
                    && File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.bypass_methods.Add("Regedit opened after minecraft start Date: " + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) + " please investigate");
                }
                else if (SMTHelper.prefetchfiles[j].ToUpper().Contains("PIF")
                    && File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.bypass_methods.Add("File with \"pif\" extension was opened after Minecraft start: " + SMTHelper.prefetchfiles[j] + " Date:" + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]));
                }
                else if (Path.GetFileName(SMTHelper.prefetchfiles[j]).ToUpper().Contains("REGSVR32.EXE"))
                {
                    for (int i = 0; i < Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames.Count; i++)
                    {
                        if (Path.GetExtension(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]).ToUpper() == ".DLL"
                            && Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i].Length > 0
                        && !Directory.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i])
                        && Path.GetExtension(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]).Length > 0
                        && File.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i])
                        && SMTHelper.IsExternalClient(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]))
                        {
                            SMT.RESULTS.bypass_methods.Add("DLL injected with cmd: " + Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]);
                        }
                        else if (File.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]))
                        {
                            SMT.RESULTS.bypass_methods.Add($"DLL from {SMTHelper.prefetchfiles[j]} missed | More informations: " + Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]);
                        }
                    }
                }
            }

            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (key.GetValue("EnablePrefetcher").ToString() != "3")
            {
                SMT.RESULTS.bypass_methods.Add("Prefetch is not active correctly, probable partial or complete disablement");
            }
        } //Refractored

        public void USNJournal()
        {
            #region Variabili

            string[] GetPrefetch_files = Directory.GetFiles(@"C:\Windows\Prefetch\", "*.pf");
            string[] GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp");

            Regex GetCorrect_file = new Regex(",.*?PF");
            Regex Exe_file = new Regex(",\".*?\",");
            Regex virgole = new Regex(",");
            Regex apostrofo = new Regex("\"");
            Regex Get_Wmic = new Regex(",\".*?\",");
            Regex JNativeHook_file = new Regex("JNATIVEHOOK.*?DLL");
            Regex GetData = new Regex("\",\".*?\",");

            Dictionary<string, string> File_And_Date = new Dictionary<string, string>();

            #endregion

            string[] usn_results = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
            string file_missed = "";
            string data_fiunzoa = "";

            for (int j = 0; j < usn_results.Length; j++)
            {
                /*
                 *  1° Rinominazione
                 *  2° Wmic
                 *  3° cacls
                 *  4° Deleted .exe
                 *  5° Deleted .pf
                 *  6° Deleted JNativeHook
                 */

                if (usn_results[j].Contains("0x00001000") && (usn_results[j].ToUpper().Contains("JNATIVEHOOK") || usn_results[j].ToUpper().Contains(".PF") || usn_results[j].ToUpper().Contains(".EXE")))
                {
                    Match GetFile_match = Exe_file.Match(usn_results[j].ToUpper());
                    file_missed = virgole.Replace(GetFile_match.Value, "");
                    file_missed = apostrofo.Replace(file_missed, "");

                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Path.GetExtension(file_missed).ToUpper() == ".EXE" && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        for (int i = 0; i < GetPrefetch_files.Length; i++)
                        {
                            if (Path.GetFileName(GetPrefetch_files[i].ToUpper()).Contains(Path.GetFileName(file_missed.ToUpper())))
                            {
                                for (int f = 0; f < Prefetch.PrefetchFile.Open(GetPrefetch_files[i]).Filenames.Count; f++)
                                {
                                    if (Path.GetFileName(Prefetch.PrefetchFile.Open(GetPrefetch_files[i]).Filenames[f].ToUpper()) == file_missed.ToUpper())
                                    {
                                        SMT.RESULTS.possible_replaces.Add($"{file_missed} was moved/renamed ({data_fiunzoa})");
                                    }
                                }
                            }
                        }
                    }
                }
                else if (usn_results[j].Contains("0x80200120"))
                {
                    Match GetWmicFile = Get_Wmic.Match(usn_results[j].ToUpper());
                    file_missed = virgole.Replace(GetWmicFile.Value, "");
                    file_missed = apostrofo.Replace(file_missed, "");

                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (DateToCompare >= SMTHelper.PC_StartTime())
                    {
                        SMT.RESULTS.bypass_methods.Add($@"Wmic found on: {file_missed} ({data_fiunzoa})");
                    }
                }
                else if (usn_results[j].Contains("0x00000800") && usn_results[j].Contains("Prefetch"))
                {
                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (DateToCompare >= SMTHelper.PC_StartTime())
                    {
                        SMT.RESULTS.bypass_methods.Add($@"Shitty method found (cacls) {data_fiunzoa}");
                    }
                }
                else if (usn_results[j].ToUpper().Contains(".EXE"))
                {
                    Match ExeFile = Exe_file.Match(usn_results[j].ToUpper());
                    file_missed = virgole.Replace(ExeFile.Value, "");
                    file_missed = apostrofo.Replace(file_missed, "");

                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Path.GetExtension(file_missed).ToUpper() == ".EXE" && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        for (int i = 0; i < GetPrefetch_files.Length; i++)
                        {
                            if (Path.GetFileName(GetPrefetch_files[i].ToUpper()).Contains(Path.GetFileName(file_missed.ToUpper())))
                            {
                                for (int f = 0; f < Prefetch.PrefetchFile.Open(GetPrefetch_files[i]).Filenames.Count; f++)
                                {
                                    if (Path.GetFileName(Prefetch.PrefetchFile.Open(GetPrefetch_files[i]).Filenames[f].ToUpper()) == file_missed.ToUpper())
                                    {
                                        SMT.RESULTS.possible_replaces.Add($"{file_missed} deleted after Minecraft start ({data_fiunzoa})");
                                    }
                                }
                            }
                        }
                    }
                }
                else if (usn_results[j].ToUpper().Contains(".PF"))
                {
                    Match GetFile_match = GetCorrect_file.Match(usn_results[j].ToUpper());
                    file_missed = virgole.Replace(GetFile_match.Value, "");
                    file_missed = apostrofo.Replace(file_missed, "");

                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Path.GetExtension(file_missed).ToUpper() == ".PF"
                        && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        SMT.RESULTS.prefetch_files_deleted.Add($"{file_missed} deleted from prefetch ({data_fiunzoa})");
                    }
                }
                else if (usn_results[j].ToUpper().Contains("JNATIVEHOOK"))
                {
                    Match GetFile_match = JNativeHook_file.Match(usn_results[j].ToUpper());
                    file_missed = virgole.Replace(GetFile_match.Value, "");
                    file_missed = apostrofo.Replace(file_missed, "");

                    Match mch = GetData.Match(usn_results[j]);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Path.GetExtension(file_missed).ToUpper() == ".DLL"
                        && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        SMT.RESULTS.generic_jnas.Add($"Generic JnativeHook clicker found (deleted)");
                    }
                }
            }

            #region Vecchi Checks

            //string MissedFile, directory, directory2;
            //MissedFile = directory = directory2 = "";

            //        if (line.ToUpper().Contains(".PF") && line.ToUpper().Contains("-") && line.Contains(Today.ToString("d")))
            //        {
            //            for (int i = 0; i < GetPrefetch_files.Length; i++)
            //            {
            //                Match GetFile_match = GetCorrect_file.Match(line.ToUpper());
            //                MissedFile = GetFile_match.Value;
            //                MissedFile = virgole.Replace(MissedFile, "");
            //                MissedFile = apostrofo.Replace(MissedFile, "");

            //                if (Path.GetFileName(GetPrefetch_files[i].ToUpper()).Contains(Path.GetFileName(MissedFile.ToUpper())))
            //                {
            //                    FileCounter_exit++;
            //                }
            //            }

            //            if (FileCounter_exit == 0)
            //            {
            //                primo = true;
            //            }

            //            if (primo)
            //            {
            //                Match get_correct_data = data.Match(line);
            //                data_fiunzoa = virgole.Replace(get_correct_data.Value, "");
            //                data_fiunzoa = apostrofo.Replace(get_correct_data.Value, "");

            //                DateTime sda = DateTime.Parse(data_fiunzoa);

            //                if (sda > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
            //                {
            //                    SMT.RESULTS.prefetch_files_deleted.Add("User deleted this prefetch log after Minecraft start - Informations: " + Path.GetFileName("File: " + MissedFile.ToUpper()) + " Date: " + data_fiunzoa);
            //                }
            //            }

            //            FileCounter_exit = 0;
            //            primo = false;
            //        }
            //        else if (line.ToUpper().Contains("JNATIVEHOOK") && line.ToUpper().Contains(".DLL") && line.Contains(Today.ToString("d")))
            //        {
            //            for (int i = 0; i < GetTemp_files.Length; i++)
            //            {
            //                Match GetFile_match = JNativeHook_file.Match(line.ToUpper());
            //                MissedFile = GetFile_match.Value;
            //                MissedFile = virgole.Replace(MissedFile, "");
            //                MissedFile = apostrofo.Replace(MissedFile, "");

            //                if (Path.GetFileName(GetTemp_files[i].ToUpper()).Contains(Path.GetFileName(MissedFile.ToUpper())))
            //                {
            //                    FileCounter_exit++;
            //                }
            //            }

            //            if (FileCounter_exit == 0)
            //            {
            //                primo = true;
            //            }

            //            if (primo)
            //            {
            //                Match get_correct_data = data.Match(line);
            //                data_fiunzoa = virgole.Replace(get_correct_data.Value, "");
            //                data_fiunzoa = apostrofo.Replace(get_correct_data.Value, "");

            //                DateTime sda = DateTime.Parse(data_fiunzoa);

            //                if (sda > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
            //                {
            //                    SMT.RESULTS.generic_jnas.Add("Generic JNativeHook Clicker (deleted) - Informations: " + Path.GetFileName("File: " + MissedFile.ToUpper()) + " Date: " + data_fiunzoa);
            //                }
            //            }

            //            FileCounter_exit = 0;
            //            primo = false;
            //        }
            //        else if (line.Contains("0x00001000") && (line.ToUpper().Contains("JNATIVEHOOK") || line.ToUpper().Contains(".PF") || line.ToUpper().Contains(".EXE")) && line.Contains(Today.ToString("d")))
            //        {
            //            Match GetFile_match = Exe_file.Match(line.ToUpper());
            //            MissedFile = virgole.Replace(GetFile_match.Value, "");
            //            MissedFile = apostrofo.Replace(MissedFile, "");

            //            Match get_correct_data = data.Match(line);
            //            data_fiunzoa = virgole.Replace(get_correct_data.Value, "");
            //            data_fiunzoa = apostrofo.Replace(get_correct_data.Value, "");

            //            Match GetDirectory = GetID.Match(line);
            //            directory = leva_primevirgole.Replace(GetDirectory.Value, "");
            //            directory = replace0x.Replace(directory, "");
            //            directory = virgole.Replace(directory, "");
            //            directory = apostrofo.Replace(directory, "");
            //            Match get_correct_string = getaddress.Match(directory);

            //            Match GetDirectory2 = GetSecondID.Match(line);
            //            directory2 = virgole.Replace(GetDirectory2.Value, "");
            //            directory2 = apostrofo.Replace(directory2, "");

            //            DateTime sda = DateTime.Parse(data_fiunzoa);

            //            if (sda > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime
            //                && !MissedFile.ToUpper().Contains("SIGCHECK.EXE")
            //                && !MissedFile.ToUpper().Contains("STRINGS2.EXE"))
            //            {
            //                for (int i = 0; i < GetPrefetch_files.Length; i++)
            //                {
            //                    if (Path.GetFileName(GetPrefetch_files[i].ToUpper()).Contains(Path.GetFileName(MissedFile.ToUpper())))
            //                    {
            //                        NtFile first_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                                FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);

            //                        NtFile second_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                                FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);

            //                        if (first_dir.NormalizedFileName != string.Empty)
            //                            SMT.RESULTS.possible_replaces.Add($@"C:{first_dir.NormalizedFileName}\{MissedFile} was moved/renamed ({data_fiunzoa})");
            //                        else
            //                            SMT.RESULTS.possible_replaces.Add($@"C:{second_dir.NormalizedFileName}\{MissedFile} was moved/renamed ({data_fiunzoa})");
            //                    }
            //                }
            //            }
            //        }
            //        else if ((line.ToUpper().Contains("JNATIVEHOOK") || line.ToUpper().Contains(".PF") || line.ToUpper().Contains(".EXE")) && line.Contains(Today.ToString("d")))
            //        {
            //            Match GetFile_match = Exe_file.Match(line.ToUpper());
            //            MissedFile = virgole.Replace(GetFile_match.Value, "");
            //            MissedFile = apostrofo.Replace(MissedFile, "");

            //            Match get_correct_data = data.Match(line);
            //            data_fiunzoa = virgole.Replace(get_correct_data.Value, "");
            //            data_fiunzoa = apostrofo.Replace(get_correct_data.Value, "");

            //            Match GetDirectory = GetID.Match(line);
            //            directory = leva_primevirgole.Replace(GetDirectory.Value, "");
            //            directory = replace0x.Replace(directory, "");
            //            directory = virgole.Replace(directory, "");
            //            directory = apostrofo.Replace(directory, "");
            //            Match get_correct_string = getaddress.Match(directory);

            //            Match GetDirectory2 = GetSecondID.Match(line);
            //            directory2 = virgole.Replace(GetDirectory2.Value, "");
            //            directory2 = apostrofo.Replace(directory2, "");

            //            DateTime sda = DateTime.Parse(data_fiunzoa);

            //            if (sda > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime
            //                && !MissedFile.ToUpper().Contains("SIGCHECK.EXE")
            //                && !MissedFile.ToUpper().Contains("STRINGS2.EXE"))
            //            {
            //                for (int i = 0; i < GetPrefetch_files.Length; i++)
            //                {
            //                    if (Path.GetFileName(GetPrefetch_files[i].ToUpper()).Contains(Path.GetFileName(MissedFile.ToUpper())))
            //                    {
            //                        SMT.RESULTS.possible_replaces.Add(MissedFile);

            //                        //NtFile first_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                        //        FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);

            //                        //NtFile second_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                        //        FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);


            //                        //SMT.RESULTS.possible_replaces.Add($@"C:{first_dir.NormalizedFileName}\{MissedFile} was deleted ({data_fiunzoa})");
            //                        //SMT.RESULTS.possible_replaces.Add($@"C:{second_dir.NormalizedFileName}\{MissedFile} was deleted ({data_fiunzoa})");

            //                    }
            //                }
            //            }
            //        }
            //        else if (line.Contains("0x80200120") && line.Contains(Today.ToString("d")))
            //        {
            //            Match GetWmicFile = Get_Wmic.Match(line.ToUpper());
            //            MissedFile = virgole.Replace(GetWmicFile.Value, "");
            //            MissedFile = apostrofo.Replace(MissedFile, "");

            //            Match get_correct_data = data.Match(line);
            //            data_fiunzoa = virgole.Replace(get_correct_data.Value, "");
            //            data_fiunzoa = apostrofo.Replace(get_correct_data.Value, "");

            //            Match GetDirectory = GetID.Match(line);
            //            directory = leva_primevirgole.Replace(GetDirectory.Value, "");
            //            directory = replace0x.Replace(directory, "");
            //            directory = virgole.Replace(directory, "");
            //            directory = apostrofo.Replace(directory, "");
            //            Match get_correct_string = getaddress.Match(directory);

            //            Match GetDirectory2 = GetSecondID.Match(line);
            //            directory2 = virgole.Replace(GetDirectory2.Value, "");
            //            directory2 = apostrofo.Replace(directory2, "");

            //            DateTime sda = DateTime.Parse(data_fiunzoa);

            //            if (sda > SMTHelper.PC_StartTime())
            //            {
            //                NtFile first_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                                    FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);

            //                NtFile second_dir = NtFile.OpenFileById(SMTHelper.OpenReparseDirectory("C:\\"), Convert.ToInt64(get_correct_string.Value, 16), FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
            //                                    FileShareMode.None, FileOpenOptions.OpenReparsePoint | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent);

            //                SMT.RESULTS.possible_replaces.Add($@"Wmic found on: C:{first_dir.NormalizedFileName}\{MissedFile} ({data_fiunzoa})");
            //                SMT.RESULTS.possible_replaces.Add($@"Wmic found on: C:{second_dir.NormalizedFileName}\{MissedFile} ({data_fiunzoa})");
            //            }
            //        }
            //    }
            //}
            #endregion

            for (int j = 0; j < GetTemp_files.Length; j++)
            {
                if (GetTemp_files[j].ToUpper().Contains("JNATIVEHOOK")
                    && GetTemp_files[j].ToUpper().Contains(".DLL")
                    && File.GetLastWriteTime(GetTemp_files[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.generic_jnas.Add("Generic JNativeHook clicker found");
                }
            } //Refractored
        }
    }
}