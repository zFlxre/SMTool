using SMT.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SMT
{
    public class Generics
    {
        #region Generics List Variables

        public List<string> results = new List<string>();
        public string[] alts { get; set; }
        public Dictionary<string, string> recyble_bins { get; set; }
        public string[] xray_packs { get; set; }
        public string[] recording_softwares { get; set; }
        public bool virtual_machine { get; set; }
        public bool vpn { get; set; }
        public Dictionary<string, string> processes_starts { get; set; }

        #endregion

        public void Alts_check()
        {
            int total_alts_ctr = 0;
            string launcher_profiles_line = "";

            try
            {
                //Default string -> "displayName" : "MrCreeper2010"
                string launcher_profiles_file = $@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\launcher_accounts.json";

                using (StreamReader read_launcher_profiles = new StreamReader(launcher_profiles_file))
                {
                    while ((launcher_profiles_line = read_launcher_profiles.ReadLine()) != null)
                    {
                        if (launcher_profiles_line.Contains("\"name\" :")) //Ignore all lines without displayName to get profile
                        {
                            Regex displayname_remove = new Regex(@"\"".*?:");
                            string remove_junk1 = displayname_remove.Replace(launcher_profiles_line, "-");  //"displayName" : "MrCreeper2010" -> - "MrCreeper2010"

                            Regex junkstr_remover = new Regex(@"\"".*?\""");
                            Match alt = junkstr_remover.Match(remove_junk1);  //Remove " from name || - "MrCreeper2010" -> MrCreeper2010

                            if (alt.Value.Length > 0)
                            {
                                SMT.RESULTS.alts.Add(alt.Value);
                                total_alts_ctr++;
                            }
                        }
                    }
                    read_launcher_profiles.Close();
                }
            }
            catch { SMT.RESULTS.alts.Add("No Alt(s) found(s)"); }

            if (total_alts_ctr == 0)
            {
                SMT.RESULTS.alts.Add("No Alt(s) found(s)");
            }
        } //Refractored

        public void RecycleBin_check()
        {
            //Get all Directories from C:\$Recycle.bin and check latest modification

            string[] recycleBinFolders = Directory.GetDirectories(@"C:\$Recycle.Bin\");
            foreach (string recycleBinFolder in recycleBinFolders)
            {
                FileInfo folderInfo = new FileInfo(recycleBinFolder);
                DateTime lastEditTime = File.GetLastWriteTime(@"C:\$Recycle.Bin\" + folderInfo.Name);

                SMT.RESULTS.recyble_bins.Add(folderInfo.Name, lastEditTime.ToString());
            }
        } //Refractored

        public void checkRecordingSoftwares()
        {
            int recordingProcessesFound = 0;


            //Check if there is 1 of this process's name in background
            string[] recordingprocesses = new string[]
            {
                "obs64",
                "obs32",
                "Action",
                "RadeonSettings",
                "ShareX",
                "NVIDIA Share",
                "CamRecorder",
                "Fraps",
                "recorder"
            };

            Parallel.ForEach(recordingprocesses, (index) =>
            {
                if (Process.GetProcessesByName(index).Length != 0)
                {
                    SMT.RESULTS.recording_softwares.Add(index);
                    recordingProcessesFound++;
                }
            });

        } //Refractored

        public void GetMouse()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_PointingDevice");

            foreach (ManagementObject obj in searcher.Get())
            {
                SMT.RESULTS.mouse.Add(obj["Name"].ToString());
            }
        }

        public void isVM()
        {
            //Check if tool is running in VirtualMachine

            // Thanks to https://stackoverflow.com/users/270348/robsiklos
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (ManagementObjectCollection items = searcher.Get())
                {
                    foreach (ManagementBaseObject item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();
                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                        || manufacturer.Contains("vmware")
                        || item["Model"].ToString() == "VirtualBox")
                        {
                            SMT.RESULTS.virtual_machine = true;
                        }
                    }
                }
            }
        } //Refractored

        public void isVPN()
        {
            //Check if user is using VPN
            // Thanks to https://stackoverflow.com/users/5593185/mike
            if (NetworkInterface.GetIsNetworkAvailable())
            {
                foreach (NetworkInterface Interface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (new[] { "TAP", "Windscribe", "WAN", "VPN" }.Any(c => Interface.Description.Contains(c))
                        && Interface.OperationalStatus == OperationalStatus.Up)
                    {
                        SMT.RESULTS.vpn = true;
                    }
                }
            }
        } //Refractored

        public void GetXrayResourcePack()
        {
            ///<summary>
            /// Get all json files in resource pack and check if pack's size is < 1000000kb
            /// </summary>

            try
            {
                string[] Get_ResourcePacks = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\resourcepacks\");
                string ResourcePack_line = string.Empty;

                Parallel.ForEach(Get_ResourcePacks, (resourcepack) =>
                {
                    FileInfo finfo = new FileInfo(resourcepack);
                    if (File.ReadAllText(resourcepack).Contains(".json") && finfo.Length < 1000000)
                    {
                        SMT.RESULTS.xray_packs.Add(resourcepack);
                    }
                });
            }
            catch { SMT.RESULTS.xray_packs.Add("Nothing Found"); }
        } //Refractored

        public void ProcessesStartup_Check()
        {
            //Get Process statup's time

            int explorerPID = Process.GetProcessesByName("explorer")[0].Id;
            int javaw = Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].Id;

            SMT.RESULTS.processes_starts.Add("Explorer: ", Process.GetProcessById(explorerPID).StartTime.ToString());
            SMT.RESULTS.processes_starts.Add("Javaw: ", Process.GetProcessById(javaw).StartTime.ToString());
            SMT.RESULTS.processes_starts.Add("System: ", SMTHelper.PC_StartTime().ToString());

        } //Refractored

        public void Clean()
        {
            //Clean SMT's files

            string SMT_dir = $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}";
            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c rmdir /S /Q " + SMT_dir)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process proc = new Process())
            {
                proc.StartInfo = procStartInfo;
                proc.Start();
            }
            Environment.Exit(0);
        } //Refractored
    }
}
