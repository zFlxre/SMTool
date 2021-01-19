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

        public void HeuristicMCPathScan()
        {
            string JarFile_line;
            int LibrariesIO_counter = 0;

            List<string> GetAll_SuspyDirectories = new List<string>();

            if (Directory.Exists($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\versions"))
            {
                //Hidden versions + Check Main
                foreach (string version_directory in Directory.GetDirectories($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\versions"))
                {
                    FileInfo fInfo = new FileInfo(version_directory);

                    if (fInfo.Attributes.HasFlag(System.IO.FileAttributes.Hidden))
                    {
                        SMT.RESULTS.HeuristicMC.Add("This folder has been hidden: " + version_directory + " please investigate");
                    }

                    foreach (string JarFile_InVersion in Directory.GetFiles(version_directory, "*.jar"))
                    {
                        using (StreamReader Read_JarFile = new StreamReader(JarFile_InVersion))
                        {
                            while ((JarFile_line = Read_JarFile.ReadLine()) != null)
                            {
                                if (JarFile_line.Contains("net/minecraft/client/main/") && JarFile_line.Contains(".class") && !JarFile_line.Contains("Main"))
                                {
                                    SMT.RESULTS.HeuristicMC.Add("There are +3 Mains in: " + JarFile_InVersion);
                                }
                            }

                            Read_JarFile.Close();
                        }
                    }
                }

                //SerenityB26, AVIX
                foreach (string io_directory in Directory.GetDirectories($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\libraries\io"))
                {
                    if (io_directory.Length > 0)
                    {
                        ++LibrariesIO_counter;
                        GetAll_SuspyDirectories.Add(io_directory);
                    }
                }

                foreach (string Single_Directory in GetAll_SuspyDirectories)
                {
                    if (LibrariesIO_counter > 1 && !Single_Directory.Contains("netty"))
                    {
                        SMT.RESULTS.HeuristicMC.Add($@"There is another directory in C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\libraries\io called {Single_Directory}");
                    }
                }
                LibrariesIO_counter = 0;
            }
            else
            {
                SMT.RESULTS.HeuristicMC.Add(".minecraft folder unreachable");
            }

            try
            {
                if (VirtualDesktop.Desktop.Count > 1)
                {
                    SMT.RESULTS.HeuristicMC.Add($"There are {VirtualDesktop.Desktop.Count} virtual desktops," +
                        $" please press Windows + TAB and investigate");
                }
            }
            catch { SMT.RESULTS.HeuristicMC.Add("Virtual Desktop(s) unreachable"); }

        } //Refractored

        public void HeuristicCsrssCheck()
        {
            string CsrssFile_line;
            CsrssFile_line = "";
            List<string> Results_duplicated = new List<string>();

            using (StreamReader Read_CsrssFile = new StreamReader($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt"))
            {
                while ((CsrssFile_line = Read_CsrssFile.ReadLine()) != null)
                {
                    Match FullFilePath_Match = GetFullFilePath.Match(CsrssFile_line.ToUpper());

                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) == ".DLL"
                        && File.Exists(FullFilePath_Match.Value)
                        && File.ReadAllText(FullFilePath_Match.Value).Contains("__std_type_info_destroy_list")
                        && File.ReadAllText(FullFilePath_Match.Value).Contains("__C_specific_handler")
                        && File.ReadAllText(FullFilePath_Match.Value).Contains("memset")
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned"))
                    {
                        SMT.RESULTS.suspy_files.Add("Injected dll found: " + FullFilePath_Match.Value);
                    }
                    if (FullFilePath_Match.Value.Length > 0
                        && !Directory.Exists(FullFilePath_Match.Value)
                        && Path.GetExtension(FullFilePath_Match.Value).Length > 0
                        && Path.GetExtension(FullFilePath_Match.Value) == ".EXE"
                        && SMTHelper.GetSign(FullFilePath_Match.Value).Contains("Unsigned"))
                    {
                        SMT.RESULTS.suspy_files.Add("File unsigned: " + FullFilePath_Match.Value);
                    }
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
                        if (File.Exists(FullFilePath_Match.Value)
                            && File.ReadLines(FullFilePath_Match.Value).First()[0] == 'M'
                            && File.ReadLines(FullFilePath_Match.Value).First()[1] == 'Z'
                            && File.ReadLines(FullFilePath_Match.Value).First() == "This program cannot be run in DOS mode"
                            && File.ReadAllText(FullFilePath_Match.Value).Contains("__std_type_info_destroy_list")
                            && File.ReadAllText(FullFilePath_Match.Value).Contains("__C_specific_handler")
                            && File.ReadAllText(FullFilePath_Match.Value).Contains("memset"))
                        {
                            SMT.RESULTS.suspy_files.Add($"Fake {Path.GetExtension(FullFilePath_Match.Value)} found: {FullFilePath_Match.Value}");
                        }
                        else
                        {
                            SMT.RESULTS.suspy_files.Add($"Fake {Path.GetExtension(FullFilePath_Match.Value)} doesn't exist | File: {FullFilePath_Match.Value}");
                        }
                    }
                }
            }
            SMT.RESULTS.suspy_files.Sort();
        } //Refractored

        public void StringScannerSystem(string link, char separator, string result)
        {
            //StringScanner system by GabTeix (https://github.com/GabTeix) (project removed)
            string[] file_lines = File.ReadAllLines(result);

            string[] javaw_scanner = File.ReadAllLines(result);

            WebClient client = new WebClient();
            string cheat, client_str;
            Regex GetFullFilePath = new Regex("^[A-Z]:.*?EXE");

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

                            if (link == "https://pastebin.com/raw/YtQUM50C")
                            {
                                Regex get_file = new Regex("!!.*?!");
                                Regex get_file2 = new Regex("!!");
                                Regex get_file3 = new Regex("!");
                                for (int j = 0; j < file_lines.Length; j++)
                                {
                                    if (file_lines[j].Contains(client_str))
                                    {
                                        string filename = "";
                                        Match remove_false = get_file.Match(file_lines[j]);
                                        filename = get_file2.Replace(remove_false.Value, "");
                                        filename = get_file3.Replace(filename, "");

                                        if (!string.IsNullOrEmpty(filename))
                                        {
                                            string[] pcasvc_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\pcasvc.txt");
                                            for (int i = 0; i < pcasvc_lines.Length; i++)
                                            {
                                                Match GetFullFilePath_match = GetFullFilePath.Match(pcasvc_lines[i].ToUpper());

                                                if (GetFullFilePath_match.Value.Length > 0 && GetFullFilePath_match.Value.Contains(filename.ToUpper()))
                                                {
                                                    SMT.RESULTS.string_scan.Add("Out of instance: " + cheat + " || File name: " + GetFullFilePath_match.Value);
                                                }
                                            }
                                        }
                                        else
                                        {
                                            clientsdetected.Add("Out of instance: " + cheat + " || File name: Impossible to get filename, possible special char");
                                        }
                                    }
                                }


                            }
                            else if (link == "https://pastebin.com/raw/bBtUqdJN")
                            {
                                if (javaw_scanner.Contains(client_str))
                                {
                                    SMT.RESULTS.string_scan.Add("Out of instance: " + cheat);
                                }
                            }
                            else if (link == "https://pastebin.com/raw/zh0UaeG4")
                            {
                                if (javaw_scanner.Contains(client_str) && !cheat.Contains("Found Generic")
                                    && (can_scan == false || can_scan))
                                {
                                    SMT.RESULTS.string_scan.Add("In instance: " + cheat);
                                }
                            }
                            else if (link == "https://pastebin.com/raw/byHrvMm9")
                            {
                                if (file_lines.Contains(client_str))
                                {
                                    SMT.RESULTS.string_scan.Add("Out of instance:" + cheat);
                                }
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
                //header.Stages(4, "String Scan Check (Scanning DPS)");
                StringScannerSystem("https://pastebin.com/raw/YtQUM50C", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
            }

            if (SMTHelper.DNS)
            {
                //header.Stages(4, "String Scan Check (Scanning Dnscache)");

                StringScannerSystem("https://pastebin.com/raw/BJ388A4H", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
            }

            if (SMTHelper.Javaw)
            {
                //header.Stages(4, "String Scan Check (Scanning Javaw)");

                StringScannerSystem("https://pastebin.com/raw/zh0UaeG4", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");

            }

            if (SMTHelper.DiagTrack)
            {
                string line = "";

                using (StreamReader sr = new StreamReader($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt"))
                {
                    while ((line = sr.ReadLine()) != null)
                    {
                        if ((line.Contains("cmd.exe") && line.Contains("del")) || line.Contains("/c ping 1.1.1.1 -n 1 -w 3000 > nul & del /f /q"))
                        {
                            SMT.RESULTS.string_scan.Add($"Out of instance: Generic Command Line self-destruct Found!");
                        }
                    }
                }
            }

        } //Refractored

        public void SaveJavaw()
        {
            if (can_scan && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
            {
                SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -pid {Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\javaw.txt");
                SMTHelper.Javaw = true;
            }
        }

        public void SaveJournal()
        {
            if (can_scan && Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
            {
                SMTHelper.SaveFile($"fsutil usn readjournal c: csv | findstr /i /C:\"" + "0x80000200" + "\"" + " /C:\"" + "0x00001000" + "\"" + " /C:\"" + "0x80200120" + "\"" + $@" > C:\ProgramData\SMT-{SMTHelper.SMTDir}\usn_results.txt");
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
                    SMTHelper.SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {SMTHelper.GetPID("pcasvc")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\pcasvc.txt");
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

            List<string> ChangeTime_list = new List<string>();

            foreach (EventLogEntry eventlogentry in GetSecurity_log.Entries)
            {
                if (eventlogentry.InstanceId == 1102 && SMTHelper.PC_StartTime() < eventlogentry.TimeGenerated)
                {
                    SMT.RESULTS.event_viewer_entries.Add($"Security Event viewer logs deleted today");
                }

                if (eventlogentry.InstanceId == 4616 && SMTHelper.PC_StartTime() <= eventlogentry.TimeGenerated)
                {
                    ChangeTime_list.Add(eventlogentry.TimeGenerated.ToString());
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
                    DateTime UpdatedTime = (DateTime)dodo.TimeCreated;

                    if (dodo.TimeCreated > SMTHelper.PC_StartTime() && UpdatedTime.AddMinutes(-5) > SMTHelper.PC_StartTime())
                    {
                        SMT.RESULTS.bypass_methods.Add($"Explorer restarted at {dodo.TimeCreated}");
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

            List<string> ChangeTime_distincted = ChangeTime_list.Distinct().ToList();

            if (ChangeTime_distincted.Count != ChangeTime_list.Count)
            {
                SMT.RESULTS.event_viewer_entries.Add("There is a 4616 event in Security on Eventvwr, probably System time change");
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
            }

            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (key.GetValue("EnablePrefetcher").ToString() != "3")
            {
                SMT.RESULTS.bypass_methods.Add("Prefetch is not active correctly, probable partial or complete disablement");
            }
        } //Refractored

        public string IndirizzoFormattato(string indirizzo)
        {
            string valore_di_ritorno = "";

            for (int i = 0; i < indirizzo.Length; i++)
            {
                if (indirizzo[i] == '0')
                {
                    valore_di_ritorno = indirizzo[i].ToString();
                    break;
                }
            }

            Regex peppe = new Regex(valore_di_ritorno + ".*?,", RegexOptions.IgnoreCase);
            Match mch = peppe.Match(indirizzo);

            return "0x" + mch.Value;
        }

        public byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        public static List<string> files = new List<string>();

        public void GetAllPrefetchFiles()
        {
            Regex Replace_Volume = new Regex(@"\\VOLUME.*?}");
            string[] prefetch_files = Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf");
            string[] match = { "5820FD00" };

            Parallel.ForEach(prefetch_files, (currentfile) =>
            {
                Parallel.ForEach(Prefetch.PrefetchFile.Open(currentfile).Filenames, (file_to_compare) =>
                {
                    if (File.GetLastWriteTime(currentfile) > SMTHelper.PC_StartTime()
                    && Path.GetExtension(file_to_compare.ToUpper()) == ".EXE")
                    {
                        string PeppeDuro = Replace_Volume.Replace(file_to_compare.ToUpper(), "C:");
                        SMT.RESULTS.suspy_files.Add(PeppeDuro);
                        //Parallel.ForEach(match, (byte_strings) =>
                        //{
                        //    try
                        //    {
                        //        byte[] matchBytes = StringToByteArray(byte_strings);

                        //        if (File.Exists(PeppeDuro))
                        //        {
                        //            if (SMTHelper.GetSign(PeppeDuro).Contains("Unsigned"))
                        //            {
                        //                SMT.RESULTS.suspy_files.Add("Unsigned: " + PeppeDuro);
                        //            }

                        //            if (File.ReadAllBytes(PeppeDuro) == matchBytes)
                        //            {
                        //                SMT.RESULTS.string_scan.Add("Out of instance: Generic Client found " + PeppeDuro);
                        //            }

                        //            using (FileStream fs = new FileStream(PeppeDuro, FileMode.Open))
                        //            {
                        //                int i = 0;
                        //                int readByte;
                        //                while ((readByte = fs.ReadByte()) != -1)
                        //                {
                        //                    if (matchBytes[i] == readByte)
                        //                    {
                        //                        i++;
                        //                    }
                        //                    else
                        //                    {
                        //                        i = 0;
                        //                    }
                        //                    if (i == matchBytes.Length)
                        //                    {
                        //                        SMT.RESULTS.string_scan.Add("Out of instance: Generic Client found " + PeppeDuro);
                        //                        break;
                        //                    }
                        //                }
                        //            }
                        //        }
                        //        else
                        //        {
                        //            SMT.RESULTS.suspy_files.Add($"{PeppeDuro} doesn't exist from Prefetch");
                        //        }
                        //    }
                        //    catch { }
                        //});

                        //files.Add(PeppeDuro);
                    }
                });
            });

            //files.Distinct().ToList();

            //for (int k = 0; k < files.Count(); k++)
            //{
            //    for (int j = 0; j < match.Length; j++)
            //    {
            //        try
            //        {
            //            byte[] matchBytes = StringToByteArray(match[j]);

            //            if (File.Exists(files[j]))
            //            {
            //                if (SMTHelper.GetSign(files[j]).Contains("Unsigned"))
            //                    SMT.RESULTS.suspy_files.Add("Unsigned: " + files[j]);

            //                using (FileStream fs = new FileStream(files[k], FileMode.Open))
            //                {
            //                    int i = 0;
            //                    int readByte;
            //                    while ((readByte = fs.ReadByte()) != -1)
            //                    {
            //                        if (matchBytes[i] == readByte)
            //                        {
            //                            i++;
            //                        }
            //                        else
            //                        {
            //                            i = 0;
            //                        }
            //                        if (i == matchBytes.Length)
            //                        {
            //                            SMT.RESULTS.string_scan.Add("Out of instance: Generic Client found " + files[j]);
            //                            break;
            //                        }
            //                    }
            //                }
            //            }
            //            else
            //            {
            //                SMT.RESULTS.suspy_files.Add($"{files[j]} doesn't exist from Prefetch");
            //            }
            //        }
            //        catch { }
            //    }
            //}
        }

        public List<string> file_getpath = new List<string>();

        public static Regex GetCorrectDirectory = new Regex("C:.*?$");

        public void USNJournal()
        {

            #region Variabili

            string[] GetPrefetch_files = Directory.GetFiles(@"C:\Windows\Prefetch\", "*.pf");
            string[] GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp");

            //Regex
            //Regex data = new Regex(Today.ToString("d") + ".*?,", RegexOptions.IgnoreCase);
            //Regex TraApostrofo = new Regex("\".*?\"");
            //Regex GetSecondID = new Regex("\",00.*?,");
            //Regex GetID = new Regex("\",0.*?,0x");
            //Regex leva_primevirgole = new Regex("\",.*?,");
            //Regex replace0x = new Regex(",0x");
            //Regex getaddress = new Regex("0.*?$");
            Regex Replace_Volume = new Regex(@"\\VOLUME.*?}");
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