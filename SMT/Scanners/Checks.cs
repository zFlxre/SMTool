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
            string[] CSRSS_file = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt");

            Parallel.ForEach(CSRSS_file, (index) =>
            {
                Match FullFilePath_Match = GetFullFilePath.Match(index.ToUpper());

                /*
                 * 1° Check Vape Lite/Yukio (firma digitale)
                 * 2° Check .EXE senza firma digitale
                 * 3° Check .EXE firma fasulla
                 * 4° Check .DLL
                 * 5° Check estensioni spoofate
                 */

                if (FullFilePath_Match.Success
                    && !Directory.Exists(FullFilePath_Match.Value)
                    && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                    && File.Exists(FullFilePath_Match.Value))
                {

                    #region EXE

                    if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && (SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Manthe Industries")
                        || SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Mynt SASU")))
                    {
                        SMT.RESULTS.suspy_files.Add("File with Generic Client's digital signature: " + FullFilePath_Match.Value);
                    }
                    else if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Fake"))
                    {
                        SMT.RESULTS.suspy_files.Add("Not valid digital sign on: " + FullFilePath_Match.Value + " maybe fake?");
                    }
                    else if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned"))
                    {
                        SMT.RESULTS.suspy_files.Add("File unsigned: " + FullFilePath_Match.Value);
                    }

                    #endregion

                    #region DLL e spoof

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
                    && Path.GetExtension(FullFilePath_Match.Value) == ".EXE")
                {
                    SMT.RESULTS.suspy_files.Add("File missed: " + FullFilePath_Match.Value);
                }
            });

            #region vecchio

            //using (StreamReader Read_CsrssFile = new StreamReader($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt"))
            //{
            //    while ((CsrssFile_line = Read_CsrssFile.ReadLine()) != null)
            //    {
            //        Match FullFilePath_Match = GetFullFilePath.Match(CsrssFile_line.ToUpper());

            //        /*
            //         * 1° Check Vape Lite/Yukio (firma digitale)
            //         * 2° Check .EXE senza firma digitale
            //         * 3° Check .DLL
            //         * 4° Check estensioni spoofate
            //         */

            //        if (FullFilePath_Match.Value.Length > 0
            //            && !Directory.Exists(FullFilePath_Match.Value)
            //            && Path.GetExtension(FullFilePath_Match.Value).Length > 0
            //            && File.Exists(FullFilePath_Match.Value))
            //        {
            //            if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE")
            //            {
            //                SMTHelper.Csrss_files.Add(FullFilePath_Match.Value);
            //            }

            //            if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
            //                && (SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Manthe Industries")
            //                || SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Mynt SASU")))
            //            {
            //                SMT.RESULTS.suspy_files.Add("File with Generic Client's digital signature: " + FullFilePath_Match.Value);
            //            }
            //            if (Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
            //                && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned"))
            //            {
            //                SMT.RESULTS.suspy_files.Add("File unsigned: " + FullFilePath_Match.Value);
            //            }
            //            if (Path.GetExtension(FullFilePath_Match.Value) == ".DLL"
            //                && SMTHelper.IsExternalClient(FullFilePath_Match.Value))
            //            {
            //                SMT.RESULTS.suspy_files.Add("Injected DLL found: " + FullFilePath_Match.Value);
            //            }
            //            if (Path.GetExtension(FullFilePath_Match.Value) != ".CONFIG"
            //                && Path.GetExtension(FullFilePath_Match.Value) != ".CPL"
            //                && Path.GetExtension(FullFilePath_Match.Value) != ".NODE"
            //                && Path.GetExtension(FullFilePath_Match.Value) != ".MANIFEST"
            //                && Path.GetExtension(FullFilePath_Match.Value) != ".DLL"
            //                && Path.GetExtension(FullFilePath_Match.Value) != ".EXE"
            //                && File.Exists(FullFilePath_Match.Value)
            //                && SMTHelper.IsExternalClient(FullFilePath_Match.Value))
            //            {
            //                SMT.RESULTS.suspy_files.Add($"External client found: {FullFilePath_Match.Value}");
            //            }
            //        }

            //        if (FullFilePath_Match.Value.Length > 0
            //            && !Directory.Exists(FullFilePath_Match.Value)
            //            && Path.GetExtension(FullFilePath_Match.Value).Length > 0
            //            && !File.Exists(FullFilePath_Match.Value)
            //            && Path.GetExtension(FullFilePath_Match.Value).ToUpper() == ".EXE")
            //        {
            //            SMT.RESULTS.suspy_files.Add("File missed: " + FullFilePath_Match.Value);
            //        }

            #endregion
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

            //}
            //}

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
                                || link == "https://pastebin.com/raw/bBtUqdJN"
                                || link == "https://pastebin.com/raw/byHrvMm9")
                                && file_lines.Contains(client_str))
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

            if (SMTHelper.DNS)
            {
                StringScannerSystem("https://pastebin.com/raw/BJ388A4H", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
            }

            if (SMTHelper.Javaw
                && !Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].MainWindowTitle.Contains("Badlion Client"))
            {
                StringScannerSystem("https://pastebin.com/raw/zh0UaeG4", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
            }

            Console.WriteLine("Reached!");

            //if (SMTHelper.DiagTrack)
            //{
            //    string file_lines = File.ReadAllText($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");

            //    if ((file_lines.Contains("cmd.exe") && file_lines.Contains("del") && file_lines.Contains(".pf")) || file_lines.Contains("/c ping 1.1.1.1 -n 1 -w 3000 > nul & del /f /q"))
            //    {
            //        SMT.RESULTS.string_scan.Add($"Out of instance: Generic Command Line self-destruct Found!");
            //    }
            //}

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
            if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
            {
                SMTHelper.SaveFile("fsutil usn readjournal c: csv | findstr /i /C:\"" + "0x80000200" + "\"" + " /C:\"" + "0x00001000" + "\"" + " /C:\"" + "0x80200120" + "\"" + " /C:\"" + "0x00000800" + "\"" + $@" > C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
                SMTHelper.Javaw = true;
            }
        }

        public void SaveDiagTrack()
        {
            //try
            //{
            //    if (SMTHelper.GetPID("DiagTrack") != " 0 ")
            //    {
            //        SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {SMTHelper.GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");
            //        SMTHelper.DiagTrack = true;
            //    }
            //    else
            //    {
            //        SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
            //    }
            //}
            //catch { }
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

        //public void SaveDPS()
        //{
        //    try
        //    {
        //        if (SMTHelper.GetPID("DPS") != " 0 ")
        //        {
        //            SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {SMTHelper.GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
        //            SMTHelper.DPS = true;
        //        }
        //        else
        //        {
        //            SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DPS process missed)");
        //        }
        //    }
        //    catch { }
        //}

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
            try
            {
                Parallel.ForEach(SMTHelper.prefetchfiles, (index) =>
                {
                    unicode_char = SMTHelper.ContainsUnicodeCharacter(index);

                    if (unicode_char)
                    {
                        SMT.RESULTS.bypass_methods.Add("Special char found in PREFETCH, please investigate " + index + " Used on: " + File.GetLastWriteTime(index));
                    }
                    else if (index.ToUpper().Contains("REGEDIT.EXE")
                        && File.GetLastWriteTime(index) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add("Regedit opened after minecraft start Date: " + File.GetLastWriteTime(index) + " please investigate");
                    }
                    else if (index.ToUpper().Contains("PIF")
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
                            else if (File.Exists(Prefetch.PrefetchFile.Open(index).Filenames[i]))
                            {
                                SMT.RESULTS.bypass_methods.Add($"DLL from {index} missed | More informations: " + Prefetch.PrefetchFile.Open(index).Filenames[i]);
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

            #region Oldcheck

            //    try
            //    {
            //    for (int j = 0; j < SMTHelper.prefetchfiles.Length; j++)
            //    {
            //        unicode_char = SMTHelper.ContainsUnicodeCharacter(SMTHelper.prefetchfiles[j]);

            //        if (unicode_char)
            //        {
            //            SMT.RESULTS.bypass_methods.Add("Special char found in PREFETCH, please investigate " + SMTHelper.prefetchfiles[j] + " Used on: " + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]));
            //        }
            //        else if (SMTHelper.prefetchfiles[j].ToUpper().Contains("REGEDIT.EXE")
            //            && File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
            //        {
            //            SMT.RESULTS.bypass_methods.Add("Regedit opened after minecraft start Date: " + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) + " please investigate");
            //        }
            //        else if (SMTHelper.prefetchfiles[j].ToUpper().Contains("PIF")
            //            && File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
            //        {
            //            SMT.RESULTS.bypass_methods.Add("File with \"pif\" extension was opened after Minecraft start: " + SMTHelper.prefetchfiles[j] + " Date:" + File.GetLastWriteTime(SMTHelper.prefetchfiles[j]));
            //        }
            //        else if (Path.GetFileName(SMTHelper.prefetchfiles[j]).ToUpper().Contains("REGSVR32.EXE"))
            //        {
            //            for (int i = 0; i < Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames.Count; i++)
            //            {
            //                if (Path.GetExtension(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]).ToUpper() == ".DLL"
            //                    && Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i].Length > 0
            //                && !Directory.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i])
            //                && Path.GetExtension(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]).Length > 0
            //                && File.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i])
            //                && SMTHelper.IsExternalClient(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]))
            //                {
            //                    SMT.RESULTS.bypass_methods.Add("DLL injected with cmd: " + Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]);
            //                }
            //                else if (File.Exists(Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]))
            //                {
            //                    SMT.RESULTS.bypass_methods.Add($"DLL from {SMTHelper.prefetchfiles[j]} missed | More informations: " + Prefetch.PrefetchFile.Open(SMTHelper.prefetchfiles[j]).Filenames[i]);
            //                }
            //            }
            //        }
            //    }
            //}
            //catch (UnauthorizedAccessException)
            //{
            //    ConsoleHelper.WriteLine("Prefetch's permissions was manipulated, please check prefetch's permissions and restart SMT", ConsoleColor.Yellow);
            //    Console.ReadLine();
            //}
            #endregion

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
            Regex JNativeHook_file = new Regex("JNATIVEHOOK.*?DLL");
            Regex GetData = new Regex("\",\".*?\",");

            Dictionary<string, string> File_And_Date = new Dictionary<string, string>();

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
                                SMT.RESULTS.possible_replaces.Add($"{file_missed} deleted after Minecraft ({data_fiunzoa})");
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
                                SMT.RESULTS.bypass_methods.Add($"Wmic method found: {file_missed} ({data_fiunzoa})");
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
                                SMT.RESULTS.possible_replaces.Add($"{file_missed} moved/renamed after Minecraft ({data_fiunzoa})");
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
                                SMT.RESULTS.generic_jnas.Add("Generic JNativeHook clicker found (deleted)");
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

            //for (int j = 0; j < usn_results.Length; j++)
            //{
            //    /*
            //     *  1° Rinominazione
            //     *  2° Wmic
            //     *  3° Deleted .exe
            //     *  4° Deleted .pf
            //     *  5° Deleted JNativeHook
            //     */

            //    if (usn_results[j].Contains("0x00001000")
            //        && (usn_results[j].ToUpper().Contains("JNATIVEHOOK")
            //        || usn_results[j].ToUpper().Contains(".PF")
            //        || usn_results[j].ToUpper().Contains(".EXE")))
            //    {
            //        Match GetFile_match = Exe_file.Match(usn_results[j].ToUpper());
            //        file_missed = virgole.Replace(GetFile_match.Value, "");
            //        file_missed = apostrofo.Replace(file_missed, "");

            //        Match mch = GetData.Match(usn_results[j]);
            //        data_fiunzoa = apostrofo.Replace(mch.Value, "");
            //        data_fiunzoa = virgole.Replace(data_fiunzoa, "");
            //        DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

            //        if (Path.GetExtension(file_missed).ToUpper() == ".EXE" && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
            //        {
            //            SMT.RESULTS.possible_replaces.Add($"{file_missed} was moved/renamed ({data_fiunzoa})");
            //        }
            //    }
            //    if (usn_results[j].Contains("0x80200120"))
            //    {
            //        Match GetWmicFile = Get_Wmic.Match(usn_results[j].ToUpper());
            //        file_missed = virgole.Replace(GetWmicFile.Value, "");
            //        file_missed = apostrofo.Replace(file_missed, "");

            //        Match mch = GetData.Match(usn_results[j]);
            //        data_fiunzoa = apostrofo.Replace(mch.Value, "");
            //        data_fiunzoa = virgole.Replace(data_fiunzoa, "");
            //        DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

            //        if (DateToCompare >= SMTHelper.PC_StartTime())
            //        {
            //            SMT.RESULTS.bypass_methods.Add($@"Wmic found on: {file_missed} ({data_fiunzoa})");
            //        }
            //    }
            //    if (usn_results[j].ToUpper().Contains(".EXE")
            //        && !usn_results[j].ToUpper().Contains(".PF")
            //        && !usn_results[j].ToUpper().Contains("-")
            //        && usn_results[j].ToUpper().Contains("0x80000200"))
            //    {
            //        Match ExeFile = Exe_file.Match(usn_results[j].ToUpper());
            //        file_missed = virgole.Replace(ExeFile.Value, "");
            //        file_missed = apostrofo.Replace(file_missed, "");

            //        Match mch = GetData.Match(usn_results[j]);
            //        data_fiunzoa = apostrofo.Replace(mch.Value, "");
            //        data_fiunzoa = virgole.Replace(data_fiunzoa, "");
            //        DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

            //        if (Path.GetExtension(file_missed).ToUpper() == ".EXE" && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
            //        {
            //            SMT.RESULTS.possible_replaces.Add($"{file_missed} deleted after Minecraft start ({data_fiunzoa})");
            //        }
            //    }

            //    if (usn_results[j].ToUpper().Contains(".PF")
            //        && usn_results[j].ToUpper().Contains("0x80000200"))
            //    {
            //        Match GetFile_match = GetCorrect_file.Match(usn_results[j].ToUpper());
            //        file_missed = virgole.Replace(GetFile_match.Value, "");
            //        file_missed = apostrofo.Replace(file_missed, "");

            //        Match mch = GetData.Match(usn_results[j]);
            //        data_fiunzoa = apostrofo.Replace(mch.Value, "");
            //        data_fiunzoa = virgole.Replace(data_fiunzoa, "");
            //        DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

            //        if (Path.GetExtension(file_missed).ToUpper() == ".PF"
            //            && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
            //        {
            //            SMT.RESULTS.prefetch_files_deleted.Add($"{file_missed} deleted from prefetch ({data_fiunzoa})");
            //        }
            //    }

            //    if (usn_results[j].ToUpper().Contains("JNATIVEHOOK")
            //        && usn_results[j].ToUpper().Contains("0x80000200"))
            //    {
            //        Match GetFile_match = JNativeHook_file.Match(usn_results[j].ToUpper());
            //        file_missed = virgole.Replace(GetFile_match.Value, "");
            //        file_missed = apostrofo.Replace(file_missed, "");

            //        Match mch = GetData.Match(usn_results[j]);
            //        data_fiunzoa = apostrofo.Replace(mch.Value, "");
            //        data_fiunzoa = virgole.Replace(data_fiunzoa, "");
            //        DateTime DateToCompare = DateTime.Parse(data_fiunzoa);

            //        if (Path.GetExtension(file_missed).ToUpper() == ".DLL"
            //            && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime <= DateToCompare)
            //        {
            //            SMT.RESULTS.generic_jnas.Add($"Generic JnativeHook clicker found (deleted)");
            //        }
            //    }
            //}

            for (int j = 0; j < GetTemp_files.Length; j++)
            {
                if (GetTemp_files[j].ToUpper().Contains("JNATIVEHOOK")
                    && GetTemp_files[j].ToUpper().Contains(".DLL")
                    && File.GetLastWriteTime(GetTemp_files[j]) > Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.generic_jnas.Add("Generic JNativeHook clicker found");
                }
            }
        }
    }
}