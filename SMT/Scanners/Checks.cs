using Microsoft.Win32;
using SMT.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Management;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SMT.scanners
{
    public class Checks
    {
        public Header header = new Header();
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
            string[] CSRSS_file = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt");

            Parallel.ForEach(CSRSS_file, (index) =>
            {
                Match FullFilePath_Match = GetFullFilePath.Match(index.ToUpper());

                /*
                 * 1° Check Vape Lite/Yukio (firma digitale)
                 * 2° Check .EXE firma fasulla
                 * 3° Check .EXE senza firma
                 * 4° Check mouse_event in C:\Windows\
                 * 5° Check Null Client
                 */

                bool isFileInPrefetch = Array.Exists(SMTHelper.prefetchfiles, E => E.Contains(Path.GetFileName(FullFilePath_Match.Value)));
                bool isFilePrefetchCurrent = Array.Exists(SMTHelper.prefetchfiles, E => File.GetLastWriteTime(E) >= SMTHelper.PC_StartTime());

                if (FullFilePath_Match.Success
                    && !Directory.Exists(FullFilePath_Match.Value)
                    && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                    && File.Exists(FullFilePath_Match.Value)
                    && isFileInPrefetch
                    && isFilePrefetchCurrent)
                {

                    #region EXE

                    if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && (SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Manthe Industries")
                        || SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Mynt SASU")))
                    {
                        SMT.RESULTS.suspy_files.Add(SMTHelper.Detection("Suspicious File", FullFilePath_Match.Value, "No time"));
                    }
                    else if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Fake"))
                    {
                        SMT.RESULTS.suspy_files.Add(SMTHelper.Detection("Fake digital signature", FullFilePath_Match.Value, "No time"));
                    }
                    else if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned")
                        && !FullFilePath_Match.Value.Contains(@"C:\WINDOWS"))
                    {
                        SMT.RESULTS.suspy_files.Add(SMTHelper.Detection("Suspicious File", FullFilePath_Match.Value, "No time"));
                    }
                    else if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned")
                        && FullFilePath_Match.Value.Contains(@"C:\WINDOWS")
                        && File.ReadAllText(FullFilePath_Match.Value).Contains("mouse_event"))
                    {
                        SMT.RESULTS.suspy_files.Add(SMTHelper.Detection("Suspicious File", FullFilePath_Match.Value, "No time"));
                    }

                    #endregion

                    #region Check Null Client

                    else if (SMTHelper.SHA256CheckSum(FullFilePath_Match.Value) == "GcMgHGh+I4ZYGFtxUXCvrMuEdGfkmj9kIokTuxMfHwk=")
                    {
                        SMT.RESULTS.suspy_files.Add("Null Client found: " + FullFilePath_Match.Value);
                    }

                    #endregion

                }
                else if (FullFilePath_Match.Success
                    && !Directory.Exists(FullFilePath_Match.Value)
                    && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                    && !File.Exists(FullFilePath_Match.Value)
                    && Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                    && isFileInPrefetch
                    && isFilePrefetchCurrent)
                {
                    SMT.RESULTS.suspy_files.Add(SMTHelper.Detection("Deleted", FullFilePath_Match.Value, "No time"));
                }

            });

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

            string file_lines = File.ReadAllText(result, Encoding.Default);

            WebClient client = new WebClient();
            string cheat, client_str;

            List<string> clientsdetected = new List<string>();
            ManagementClass mngmtClass = new ManagementClass("Win32_Process");

            foreach (ManagementObject o in mngmtClass.GetInstances())
            {
                if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
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
                                || link == "https://pastebin.com/raw/BJ388A4H")
                                && file_lines.ToLower().Contains(client_str))
                            {
                                SMT.RESULTS.string_scan.Add("Out of instance: " + cheat);
                            }
                            else if (link == "https://pastebin.com/raw/zh0UaeG4"
                                && can_scan
                                && file_lines.Contains(client_str)
                                && !cheat.Contains("Found Generic"))
                            {
                                SMT.RESULTS.string_scan.Add("In instance: " + cheat);
                            }
                        }
                    }
                }
            }

            //file_lines = new string[] { };

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

            if (SMTHelper.lsass)
            {
                StringScannerSystem("https://pastebin.com/raw/BJ388A4H", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\dns.txt");
            }

            if (SMTHelper.DNS)
            {
                StringScannerSystem("https://pastebin.com/raw/BJ388A4H", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
            }

            if (SMTHelper.Javaw)
            {
                StringScannerSystem("https://pastebin.com/raw/zh0UaeG4", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
            }
        } //Refractored

        public void SaveJavaw()
        {
            if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0
                && !Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].MainWindowTitle.Contains("Badlion Client")
                && !Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].MainWindowTitle.Contains("Lunar Client"))
            {
                SMTHelper.UnProtectProcess(Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id);
                SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -a -pid {Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
                SMTHelper.Javaw = true;
            }
        }

        public void SaveJournal()
        {
            SMTHelper.SaveFile("fsutil usn readjournal c: csv | findstr /i /C:\"" + "0x80000200" + "\"" + " /C:\"" + "0x00001000" + "\"" + " /C:\"" + "0x80200120" + "\"" + " /C:\"" + "0x00000800" + "\"" + $@" > C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
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
                        SMT.RESULTS.bypass_methods.Add("USB connected at: " + dodo.TimeCreated);
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
            try
            {
                Parallel.ForEach(SMTHelper.prefetchfiles, (index) =>
                {
                    unicode_char = SMTHelper.ContainsUnicodeCharacter(index);

                    if (unicode_char)
                    {
                        SMT.RESULTS.bypass_methods.Add($"File with special char found: {index} ({File.GetLastWriteTime(index)})");
                    }
                    else if (index.ToUpper().Contains("REGEDIT.EXE")
                        && File.GetLastWriteTime(index) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add("Regedit opened after minecraft start Date: " + File.GetLastWriteTime(index) + " please investigate");
                    }
                    else if (index.ToUpper().Contains(".PIF-")
                        && File.GetLastWriteTime(index) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add("File with \"pif\" extension was opened after Minecraft start: " + index + " Date:" + File.GetLastWriteTime(index));
                    }
                    else if (Path.GetFileName(index).ToUpper().Contains("REGSVR32.EXE"))
                    {
                        for (int i = 0; i < Prefetch.PrefetchFile.Open(index).Filenames.Count; i++)
                        {
                            if (Path.GetExtension(Prefetch.PrefetchFile.Open(index).Filenames[i]).ToUpper() == ".DLL"
                                && Prefetch.PrefetchFile.Open(index).Filenames[i].Length > 0
                            && !Directory.Exists(Prefetch.PrefetchFile.Open(index).Filenames[i])
                            && Path.GetExtension(Prefetch.PrefetchFile.Open(index).Filenames[i]).Length > 0
                            && File.Exists(Prefetch.PrefetchFile.Open(index).Filenames[i])
                            && SMTHelper.IsExternalClient(Prefetch.PrefetchFile.Open(index).Filenames[i]))
                            {
                                SMT.RESULTS.bypass_methods.Add("DLL injected with cmd: " + Prefetch.PrefetchFile.Open(index).Filenames[i]);
                            }
                            else if (!File.Exists(Prefetch.PrefetchFile.Open(index).Filenames[i]))
                            {
                                SMT.RESULTS.bypass_methods.Add($"DLL from {index} missed (Possible replace) | More informations: " + Prefetch.PrefetchFile.Open(index).Filenames[i]);
                            }
                        }
                    }
                });
            }
            catch (UnauthorizedAccessException)
            {
                SMT.RESULTS.Errors.Add("Prefetch's permissions was manipulated, please check prefetch's permissions and restart SMT");
                ConsoleHelper.WriteLine("Prefetch's permissions was manipulated, please check prefetch's permissions and restart SMT", ConsoleColor.Yellow);
                Console.ReadLine();
                Environment.Exit(1);
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

            string[] GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp");

            Regex GetCorrect_file = new Regex(",.*?PF");
            Regex Exe_file = new Regex(",\".*?\",");
            Regex virgole = new Regex(",");
            Regex apostrofo = new Regex("\"");
            Regex GetData = new Regex("\",\".*?\",");

            #endregion

            string[] usn_results = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
            string data_fiunzoa = "";
            string file_missed = "";

            Parallel.ForEach(usn_results, (index) =>
            {
                /*
                 * Eliminati
                 * Wmic
                 * Moved/Renamed
                 * JNativeHook
                 * .PF
                 */

                if (index.ToUpper().Contains(".EXE") && !index.ToUpper().Contains(".PF") && index.Contains("0x80000200"))
                {
                    Match mch = GetData.Match(index);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        Match GetFile_match = Exe_file.Match(index.ToUpper());

                        if (GetFile_match.Success)
                        {
                            file_missed = virgole.Replace(GetFile_match.Value, "");
                            file_missed = apostrofo.Replace(file_missed, "");

                            if (Path.GetExtension(file_missed).ToUpper() == ".EXE")
                            {
                                string directory = SMTHelper.GetDirectoryFromID(index, file_missed);

                                if (directory.Contains(":\\"))
                                {
                                    SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection("Deleted", directory, data_fiunzoa));
                                }
                            }
                        }
                    }
                }
                if (index.Contains("0x80200120"))
                {
                    Match mch = GetData.Match(index);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (SMTHelper.PC_StartTime() <= DateToCompare)
                    {
                        Match GetFile_match = Exe_file.Match(index.ToUpper());

                        if (GetFile_match.Success)
                        {
                            file_missed = virgole.Replace(GetFile_match.Value, "");
                            file_missed = apostrofo.Replace(file_missed, "");

                            if (Path.GetExtension(file_missed).Length > 0)
                            {
                                string directory = SMTHelper.GetDirectoryFromID(index, file_missed);

                                if (directory.Contains(":\\"))
                                {
                                    SMT.RESULTS.bypass_methods.Add($"Wmic method found: {directory} ({data_fiunzoa})");
                                }
                            }
                        }
                    }
                }
                if (index.ToUpper().Contains(".EXE") && index.Contains("0x00001000"))
                {
                    Match mch = GetData.Match(index);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        Match GetFile_match = Exe_file.Match(index.ToUpper());

                        if (GetFile_match.Success)
                        {
                            file_missed = virgole.Replace(GetFile_match.Value, "");
                            file_missed = apostrofo.Replace(file_missed, "");

                            if (Path.GetExtension(file_missed).ToUpper() == ".EXE")
                            {
                                string directory = SMTHelper.GetDirectoryFromID(index, file_missed);

                                if (directory.Contains(":\\"))
                                {
                                    SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection("Moved/Renamed", directory, data_fiunzoa));
                                }
                            }
                        }
                    }
                }
                if (index.ToUpper().Contains("JNATIVEHOOK") && index.Contains("0x80000200"))
                {
                    Match mch = GetData.Match(index);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        Match GetFile_match = Exe_file.Match(index.ToUpper());

                        if (GetFile_match.Success)
                        {
                            file_missed = virgole.Replace(GetFile_match.Value, "");
                            file_missed = apostrofo.Replace(file_missed, "");

                            if (Path.GetExtension(file_missed).ToUpper() == ".DLL")
                            {
                                SMT.RESULTS.generic_jnas.Add(SMTHelper.Detection("Deleted", "Generic JNativeHook Clicker (deleted)", data_fiunzoa));
                            }
                        }
                    }
                }
                if (index.ToUpper().Contains(".EXE") && index.ToUpper().Contains(".PF") && index.Contains("0x80000200"))
                {
                    Match mch = GetData.Match(index);
                    data_fiunzoa = apostrofo.Replace(mch.Value, "");
                    data_fiunzoa = virgole.Replace(data_fiunzoa, "");
                    DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

                    if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
                    {
                        Match GetFile_match = Exe_file.Match(index.ToUpper());

                        if (GetFile_match.Success)
                        {
                            file_missed = virgole.Replace(GetFile_match.Value, "");
                            file_missed = apostrofo.Replace(file_missed, "");

                            if (Path.GetExtension(file_missed).ToUpper() == ".PF")
                            {
                                SMT.RESULTS.prefetch_files_deleted.Add("Prefetch value deleted after Minecraft " + file_missed + $" ({data_fiunzoa})");
                            }
                        }
                    }
                }
            });

            for (int j = 0; j < GetTemp_files.Length; j++)
            {
                if (GetTemp_files[j].ToUpper().Contains("JNATIVEHOOK")
                    && GetTemp_files[j].ToUpper().Contains(".DLL")
                    && File.GetLastWriteTime(GetTemp_files[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.generic_jnas.Add("Generic JNativeHook Clicker found");
                }
            }
        }
    }
}