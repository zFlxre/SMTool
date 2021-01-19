using System;
using System.Net;
using System.Threading;

namespace SMT.helpers
{
    public static class WebHelper
    {
        public static string DownloadString(string url)
        {
            using (WebClient wc = new WebClient())
            {
                try
                {
                    return wc.DownloadString(url);
                }
                catch
                {
                    ConsoleHelper.WriteLine("Please check your connection!", ConsoleColor.Red);
                    Thread.Sleep(5000);
                    Environment.Exit(1);
                    return string.Empty;
                }
            }
        }
    }
}