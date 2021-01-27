using SMT.helpers;
using System;
using System.Diagnostics;
using System.Reflection;

namespace SMT
{
    public class Header
    {
        public Header()
        {
            Console.Title = $"SMT v-{VERSION} (LGBT Edition)";
        }

        #region SMT's ASCII and Check Version

        public string asciiArt = @"

  ███████╗███╗   ███╗████████╗
  ██╔════╝████╗ ████║╚══██╔══╝
  ███████╗██╔████╔██║   ██║   
  ╚════██║██║╚██╔╝██║   ██║   
  ███████║██║ ╚═╝ ██║   ██║   
  ╚══════╝╚═╝     ╚═╝   ╚═╝   
                                                    Ciao amic*                " + "\n";

        public static string VERSION => FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion;
        #endregion

        private void Check_Updates()
        {
            if (VERSION != WebHelper.DownloadString("https://pastebin.com/raw/8CFatqcd"))
            {
                ConsoleHelper.WriteLine("Mhhh, why you haven't got newest SMT version? Contact me! @MattioneGrossoGrosso on Telegram\n" +
                    "Pssss SMT is free ;)", ConsoleColor.Yellow);
                SMTHelper.Exit();
                Environment.Exit(0);
            }
        }

        public void Home()
        {
            Console.CursorVisible = false;

            Check_Updates();

            foreach (string line in (asciiArt).Split('\n'))
            {
                int indent = (Console.BufferWidth - line.Length) / 2;
                string indentation = new string(' ', indent);
                ConsoleHelper.WriteLine(indentation + line, ConsoleColor.Cyan);
            }
        }

        public void Stages(int stage, string check)
        {
            Console.Clear();
            Home();

            string line = (stage != 4) ? $"Stage #{stage} {check}" : $"({SMT.getTimestamp() - SMT.startTimestamp}ms)";

            int indent = (Console.BufferWidth - line.Length) / 2;
            string indentation = new string(' ', indent);
            ConsoleHelper.WriteLine(indentation + line, ConsoleColor.Blue);
        }
    }
}
