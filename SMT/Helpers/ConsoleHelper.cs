using System;

namespace SMT
{
    public static class ConsoleHelper
    {
        public static void WriteLine(string text, ConsoleColor consoleColor = ConsoleColor.White)
        {
            ConsoleColor backupColor = Console.ForegroundColor;
            Console.ForegroundColor = consoleColor;
            Console.WriteLine(text);
            Console.ForegroundColor = backupColor;
        }

        public static void Write(string text, ConsoleColor consoleColor = ConsoleColor.White)
        {
            ConsoleColor backupColor = Console.ForegroundColor;
            Console.ForegroundColor = consoleColor;
            Console.Write(text);
            Console.ForegroundColor = backupColor;
        }
    }
}
