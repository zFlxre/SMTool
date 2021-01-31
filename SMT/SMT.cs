using SMT.helpers;
using SMT.scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SMT
{
    public static class SMT
    {
        public static Results RESULTS = new Results();
        public static readonly List<Task> tasks = new List<Task>();

        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010
        /// </summary>

        private static void ThrowException()
        {
            RESULTS.Errors.Add("An error occured meanwhile SMT was scanning, please restart SMT");
        }

        public static void runCheckAsync(Action check)
        {
            try
            {
#pragma warning disable CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
                tasks.Add(Task.Factory.StartNew(async () => check()));
#pragma warning restore CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
            }
            catch { ThrowException(); }
        }

        public static long getTimestamp()
        {
            return DateTime.Now.Ticks / 10000;
        }

        public static long startTimestamp = getTimestamp();

        public static DcHook Discord = new DcHook();

        private static void Main()
        {
            Discord.UserName = "Scan results - SMT";
            Discord.WebHook = "https://discord.com/api/webhooks/805042932662403072/fRTa7Nt2FX6DX_BVPwECmIg6l8GALZ4waat7kfS48vHaoruBSOheOTvz7qSWo0Bc_hc9";

            Header header = new Header();
            Generics generics = new Generics();
            Checks checks = new Checks();

            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
            new Thread(() => {
                while (true) {
                    foreach (ProcessThread processThread in Process.GetCurrentProcess().Threads) {
                        if (processThread.ThreadState != System.Diagnostics.ThreadState.Terminated) {
                            try {
                                processThread.PriorityLevel = ThreadPriorityLevel.TimeCritical;
                            }
                            catch {

                            }
                        }
                    }

                    Thread.Sleep(50);
                }
            }).Start();

            header.Stages(0, "Looking 4 Minecraft");

            if (SMTHelper.isCorrectMC())
            {
                #region Delete close button - ExtractFile - SaveFiles - Classes - Priority

                SMTHelper.DeleteMenu(SMTHelper.GetSystemMenu(SMTHelper.GetConsoleWindow(), false), SMTHelper.SC_CLOSE, SMTHelper.MF_BYCOMMAND);

                SMTHelper.ExtractFile();
                SMTHelper.SaveAllFiles();

                Action[] SaveAllFiles = new Action[]
                {
                    checks.SaveJournal,
                    //checks.SaveJavaw,
                    checks.HeuristicCsrssCheck, //da riguardare
                    generics.Alts_check, //funziona
                    generics.GetXrayResourcePack, //funziona
                    generics.checkRecordingSoftwares, //funziona
                    generics.isVM, //idk
                    generics.isVPN, //idk
                    generics.RecycleBin_check, //funziona
                    generics.ProcessesStartup_Check, //funziona
                    generics.GetMouse, //funziona
                    checks.OtherChecks, //funziona
                    checks.EventVwrCheck, //idk
                };

                for (int j = 0; j < SaveAllFiles.Length; j++)
                {
                    runCheckAsync(SaveAllFiles[j]);
                }

                Task.WaitAll(tasks.ToArray());

                //foreach(string dino in SMTHelper.Csrss_files)
                //{
                //    Console.WriteLine(dino);
                //}
                //Console.ReadLine();
                #endregion

                #region Check 1 e Check 2

                //checks.StringScan();

                Action[] scannerChecks = new Action[]
                {
                    checks.USNJournal,
                    //checks.StringScan,
                };

                for (int j = 0; j < scannerChecks.Length; j++)
                {
                    runCheckAsync(scannerChecks[j]);
                }

                #endregion

                #region Waiting for results

                header.Stages(1, SMTHelper.CheaterJoke());

                Task.WaitAll(tasks.ToArray());

                header.Stages(4, "");

                //ManagementObjectSearcher myVideoObject = new ManagementObjectSearcher("select * from Win32_VideoController");

                //foreach (ManagementObject obj in myVideoObject.Get())
                //{
                //    Discord.SendMessage($"Un utente ha totalizzato: {getTimestamp() - startTimestamp}ms in uno scan!\n" +
                //        "OS: " + obj["Name"] + " Versione: " + obj["DriverVersion"] +
                //        "\n RAM: " + obj["AdapterRAM"]);
                //}

                Discord.SendMessage($"Un utente ha totalizzato: {getTimestamp() - startTimestamp}ms in uno scan!\n");
                Discord.Dispose();

                #endregion

                #region Result System Generic(s) Information (Check 1)
                ConsoleHelper.WriteLine("Generic Informations: \n", ConsoleColor.Green);

                ConsoleHelper.WriteLine("Alts:\n", ConsoleColor.Yellow); //fatto
                RESULTS.alts.Distinct().ToList().ForEach(alt => ConsoleHelper.WriteLine("- " + alt));

                ConsoleHelper.WriteLine("\nRecycle.bin:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> recycleBin in RESULTS.recyble_bins)
                {
                    ConsoleHelper.WriteLine($"- {recycleBin.Value} ({recycleBin.Key})");
                }

                ConsoleHelper.WriteLine("\nRecording Software(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.recording_softwares.Count > 0)
                {
                    RESULTS.recording_softwares.ForEach(recording => ConsoleHelper.WriteLine("- " + recording));
                }
                else
                {
                    Console.WriteLine("- No Recording Software(s) found");
                }

                ConsoleHelper.WriteLine("\nProcess(es) Start Time:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> processStart in RESULTS.processes_starts)
                {
                    ConsoleHelper.WriteLine("- " + processStart.Key + processStart.Value);
                }

                ConsoleHelper.WriteLine("\nXray Resource Pack(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.xray_packs.Count > 0)
                {
                    RESULTS.xray_packs.ForEach(xray => ConsoleHelper.WriteLine("- " + xray));
                }
                else
                {
                    Console.WriteLine("- No Xray resource pack found");
                }

                ConsoleHelper.WriteLine("\nClick device(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.mouse.Count > 0)
                {
                    RESULTS.mouse.ForEach(mouse => ConsoleHelper.WriteLine("- Click device found with name: " + mouse));
                }
                else
                {
                    Console.WriteLine("- No click devices found");
                }

                if (RESULTS.virtual_machine)
                {
                    ConsoleHelper.WriteLine("\n[!] Tool is running on Virtual Machine, please investigate", ConsoleColor.Red); //fatto
                }

                if (RESULTS.vpn)
                {
                    ConsoleHelper.WriteLine("\n[!] VPN Detected!", ConsoleColor.Red); //fatto
                }
                #endregion

                #region Result System "Checks" (Check 2)

                ConsoleHelper.WriteLine("\nChecks:", ConsoleColor.Red);

                if (RESULTS.Errors.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("[-]An error occured meanwhile SMT was scanning, please restart SMT", ConsoleColor.Red);
                }

                if (RESULTS.generic_jnas.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nGeneric JNativeHook Clicker(s):\n", ConsoleColor.Cyan);
                    RESULTS.generic_jnas.Distinct().ToList().ForEach(jna => ConsoleHelper.WriteLine("- " + jna));
                }

                if (RESULTS.possible_replaces.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nDeleted/Replaced .exe file(s):\n", ConsoleColor.Cyan);
                    RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.prefetch_files_deleted.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nDeleted Prefetch Log(s):\n", ConsoleColor.Cyan);
                    RESULTS.prefetch_files_deleted.Distinct().ToList().ForEach(strscn => ConsoleHelper.WriteLine("- " + strscn));
                }

                if (RESULTS.event_viewer_entries.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nBad Eventvwr log(s):\n", ConsoleColor.Cyan);
                    RESULTS.event_viewer_entries.Distinct().ToList().ForEach(eventvwr => ConsoleHelper.WriteLine("- " + eventvwr));
                }

                if (RESULTS.suspy_files.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nUnsigned/Spoofed File(s) Check:\n", ConsoleColor.Cyan);
                    RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => ConsoleHelper.WriteLine("- " + suspy));
                }

                if (RESULTS.bypass_methods.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nBypass methods:\n", ConsoleColor.Cyan);
                    RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.string_scan.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nString Scan:\n", ConsoleColor.Cyan);
                    RESULTS.string_scan.Distinct().ToList().ForEach(strscn => ConsoleHelper.WriteLine("- " + strscn));
                }

                #endregion

                #region Nothing Found
                if (RESULTS.HeuristicMC.Count == 0 && RESULTS.prefetch_files_deleted.Count == 0
                     && RESULTS.possible_replaces.Count == 0 && RESULTS.suspy_files.Count == 0
                     && RESULTS.generic_jnas.Count == 0 && RESULTS.event_viewer_entries.Count == 0
                     && RESULTS.string_scan.Count == 0 && RESULTS.bypass_methods.Count == 0)
                {
                    ConsoleHelper.WriteLine("\nNothing Found", ConsoleColor.Green);
                }
                #endregion

                #region Exit + Clean SMT files
                ConsoleHelper.WriteLine("\nHave a nice day! developed by @MattioneGrossoGrosso", ConsoleColor.Yellow);
                Console.Write("\nPress ENTER to exit..");
                Console.ReadLine();
                Console.Write("\nConfirm exit -> press ENTER..");
                Console.ReadLine();
                generics.Clean();
                #endregion
            }
            else
            {
                header.Stages(0, "Error!");

                ConsoleHelper.WriteLine("Minecraft missed, press enter to exit", ConsoleColor.Yellow);
                Console.ReadLine();
                Environment.Exit(0);
            }
        }
    }
}