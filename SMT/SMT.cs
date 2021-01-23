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

        //TODO: USNJournal buggato

        /// <summary>
        /// Welcome to the SMT ScreenShare Tool source code.
        /// @SMTool on Telegram
        /// Developers (Telegram): @MrCreeper2010 - @doliv8 - @marco1337 - @delta9tetraidrocannabinolo (ssmath)
        /// </summary>

        //TODO: Refractoring

        private static void ThrowException()
        {
            ConsoleHelper.WriteLine("Unexpected error, try to restart the application, if the error persists contact @SMTSupport_bot on telegram (scan skipped) \n", ConsoleColor.Red);
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

        private static void Main()
        {
            #region SMT_Problem

            //TODO: Performance problems

            //Regex Replace_Volume = new Regex(@"\\VOLUME.*?}");
            //string[] prefetch_files = Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf");
            //string[] match = { "58 20 FD 00" };

            //for(int i = 0; i < prefetch_files.Length; i++)
            //{
            //   for(int j = 0; j < Prefetch.PrefetchFile.Open(prefetch_files[i]).Filenames.Count; j++)
            //    {
            //        if (File.GetLastWriteTime(prefetch_files[i]) > SMTHelper.PC_StartTime()
            //        && Path.GetExtension(Prefetch.PrefetchFile.Open(prefetch_files[i]).Filenames[j].ToUpper()) == ".EXE")
            //        {
            //            string PeppeDuro = Replace_Volume.Replace(Prefetch.PrefetchFile.Open(prefetch_files[i]).Filenames[j].ToUpper(), "C:");
            //            Console.WriteLine(PeppeDuro);
            //        }
            //    }
            //}

            //Parallel.ForEach(prefetch_files, (currentfile) =>
            //{
            //    Parallel.ForEach(Prefetch.PrefetchFile.Open(currentfile).Filenames, (file_to_compare) =>
            //    {
            //        if (File.GetLastWriteTime(currentfile) > SMTHelper.PC_StartTime()
            //        && Path.GetExtension(file_to_compare.ToUpper()) == ".EXE")
            //        {
            //            string PeppeDuro = Replace_Volume.Replace(file_to_compare.ToUpper(), "C:");
            //            Console.WriteLine(PeppeDuro);
            //        }
            //    });
            //});
            #endregion

            Header header = new Header();
            Generics generics = new Generics();
            Checks checks = new Checks();

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
                    checks.SaveJavaw,
                };

                for (int j = 0; j < SaveAllFiles.Length; j++)
                {
                    runCheckAsync(SaveAllFiles[j]);
                }

                Task.WaitAll(tasks.ToArray());

                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
                new Thread(() =>
                {
                    while (true)
                    {
                        foreach (ProcessThread processThread in Process.GetCurrentProcess().Threads)
                        {
                            if (processThread.ThreadState != System.Diagnostics.ThreadState.Terminated)
                            {
                                try
                                {
                                    processThread.PriorityLevel = ThreadPriorityLevel.TimeCritical;
                                }
                                catch
                                {

                                }
                            }
                        }

                        Thread.Sleep(50);
                    }
                }).Start();

                #endregion

                #region Check 1 e Check 2

                Action[] genericChecks = new Action[]
                {
                generics.Alts_check,
                generics.GetXrayResourcePack,
                generics.checkRecordingSoftwares,
                generics.isVM,
                generics.isVPN,
                generics.RecycleBin_check,
                generics.ProcessesStartup_Check,
                generics.GetMouse
                };

                for (int j = 0; j < genericChecks.Length; j++)
                {
                    runCheckAsync(genericChecks[j]);
                }

                Action[] scannerChecks = new Action[]
                {
                    checks.HeuristicCsrssCheck,
                    checks.EventVwrCheck,
                    checks.USNJournal,
                    checks.HeuristicMCPathScan,
                    checks.OtherChecks,
                    checks.StringScan,
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

                #endregion

                #region Result System Generic(s) Information (Check 1)
                ConsoleHelper.WriteLine("[i] Generic Informations: \n", ConsoleColor.Green);

                ConsoleHelper.WriteLine("[i] Alts:\n", ConsoleColor.Yellow); //fatto
                RESULTS.alts.ForEach(alt => ConsoleHelper.WriteLine("- " + alt));

                ConsoleHelper.WriteLine("\n[i] Recycle.bin:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> recycleBin in RESULTS.recyble_bins)
                {
                    ConsoleHelper.WriteLine($"- {recycleBin.Value} ({recycleBin.Key})");
                }

                ConsoleHelper.WriteLine("\n[i] Recording Software(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.recording_softwares.Count > 0)
                {
                    RESULTS.recording_softwares.ForEach(recording => ConsoleHelper.WriteLine("- " + recording));
                }
                else
                {
                    Console.WriteLine("- No Recording Software(s) found");
                }

                ConsoleHelper.WriteLine("\n[i] Process(es) Start Time:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> processStart in RESULTS.processes_starts)
                {
                    ConsoleHelper.WriteLine("- " + processStart.Key + processStart.Value);
                }

                ConsoleHelper.WriteLine("\n[i] Xray Resource Pack(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.xray_packs.Count > 0)
                {
                    RESULTS.xray_packs.ForEach(xray => ConsoleHelper.WriteLine("- " + xray));
                }
                else
                {
                    Console.WriteLine("- No Xray resource pack found");
                }

                ConsoleHelper.WriteLine("\n[i] Click device(s):\n", ConsoleColor.Yellow); //fatto
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

                ConsoleHelper.WriteLine("\n[s] Checks:", ConsoleColor.Red);

                if (RESULTS.generic_jnas.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Generic JNativeHook Clicker(s):\n", ConsoleColor.Cyan);
                    RESULTS.generic_jnas.Distinct().ToList().ForEach(jna => ConsoleHelper.WriteLine("- " + jna));
                }

                if (RESULTS.possible_replaces.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Deleted/Replaced .exe file(s):\n", ConsoleColor.Cyan);
                    RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.prefetch_files_deleted.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Deleted Prefetch Log(s):\n", ConsoleColor.Cyan);
                    RESULTS.prefetch_files_deleted.Distinct().ToList().ForEach(strscn => ConsoleHelper.WriteLine("- " + strscn));
                }

                if (RESULTS.event_viewer_entries.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Bad Eventvwr log(s):\n", ConsoleColor.Cyan);
                    RESULTS.event_viewer_entries.Distinct().ToList().ForEach(eventvwr => ConsoleHelper.WriteLine("- " + eventvwr));
                }

                if (RESULTS.suspy_files.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Unsigned/Spoofed File(s) Check:\n", ConsoleColor.Cyan);
                    RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => ConsoleHelper.WriteLine("- " + suspy));
                }

                if (RESULTS.bypass_methods.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] Bypass methods:\n", ConsoleColor.Cyan);
                    RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.HeuristicMC.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] .minecraft Informations:\n", ConsoleColor.Cyan);
                    RESULTS.HeuristicMC.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.string_scan.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\n[s] String Scan:\n", ConsoleColor.Cyan);
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
            }
        }
    }
}