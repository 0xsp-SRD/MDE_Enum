using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MDE_Enum
{
    internal class funcs
    {



       public  static readonly Dictionary<string, string> AsrRuleDescriptions = new Dictionary<string, string>
        {
            { "56A863A9-875E-4185-98A7-B882C64B5CE5", "Block Exploit of Vulnerable Signed Drivers" },
            { "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "Prevent Adobe Reader from creating child processes" },
            { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Prevent all Office applications from creating child processes" },
            { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem" },
            { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email client and webmail" },
            { "01443614-CD74-433A-B99E-2ECDC07BFC25", "Block executable files unless they meet a prevalence, age, or trusted list criterion" },
            { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block execution of potentially hidden scripts" },
            { "D3E037E1-3EB8-44C8-A917-57927947596D", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "3B576869-A4EC-4529-8536-B80A7769E899", "Block Office applications from creating executable content" },
            { "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "Prevent Office applications from injecting code into other processes" },
            { "26190899-1602-49E8-8B27-EB1D0A1CE869", "Block Office Communication Application from Creating Child Processes" },
            { "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", "Block persistence via WMI event subscription" },
            { "D1E49AAC-8F56-4280-B9BA-993A6D77406C", "Block Process Creations from PSExec and WMI Commands" },
            { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block computer restarting in safe mode (preview)" },
            { "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", "Block untrusted and unsigned processes running from USB" },
            { "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB", "Block the use of copied or imitated system utilities (preview)" },
            { "A8F5898E-1DC8-49A9-9878-85004B8A61E6", "Block the creation of web shells for servers" },
            { "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "Block Win32 API Calls from Office Macros" },
            { "C1DB55AB-C21A-4637-BB3F-A12568109D35", "How to use advanced ransomware protection" },
        };




        public static int Banner()
        {


            Console.WriteLine(@"
   __  ______  ____  _____  ____  ____  ___  
  /  |/  / _ \/ __/ / __/ |/ / / / /  |/  /  
 / /|_/ / // / _/  / _//    / /_/ / /|_/ /   
/_/  /_/____/___/ /___/_/|_/\____/_/  /_/    
                                             
 ");

            Console.WriteLine("By : @zux0x3a \n");
        
           Console.WriteLine("------------------Retrieve Defender Exclusion Paths Using Event Logs -------------\n");
            Console.WriteLine("Local System  : MDE_Enum /local /paths ");
            Console.WriteLine("Remote System :  MDE_Enum <remoteComputer> <username> <password> <domain> /paths\n");


            Console.WriteLine("------------------Retrieve Defender ASR Triggered Events ----------------- \n");

            Console.WriteLine("Local System - MDE_Enum /local /asr ");
            Console.WriteLine("Remote System - MDE_Enum <remoteComputer> <username> <password> <domain> /asr\n");

            Console.WriteLine("------------------Retrieve ASR rules From MSP_Preference ----------------\n");

            Console.WriteLine("Local System - MDE Enum /local /asr /alt");
            Console.WriteLine("Remote System - MDE_Enum <remoteComputer> <domain> <username> <password> /asr /alt\n");
            return 1;
        }
        public static SecureString ConvertToSecureString(string password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            SecureString securePassword = new SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();
            return securePassword;
        }

        public static string ExtractAsrRuleId(string message)
        {
            string pattern = @"ID:\s*([0-9A-FA-f\-]+)"; // regex to extract ASR formatted rules. 
            Match match = Regex.Match(message, pattern);
            return match.Success ? match.Groups[1].Value : null;
        }



        // function to draw a table of content, nicer design.
        public static void PrintTable(List<Tuple<string, string ,string>> data)
        {
            if (data.Count == 0)
            {
                Console.WriteLine("No ASR rules found.");
                return;
            }

            int idColumnWidth = data.Max(item => item.Item1.Length) + 2;
            int actionColumnWidth = data.Max(item => item.Item2.Length) + 2;
            int nameColumnWidth = data.Max(item => item.Item3.Length) + 2; 

            string separator = new string('-', idColumnWidth + actionColumnWidth + nameColumnWidth +  7);
            string header = $"| {"Enabled?".PadRight(idColumnWidth)} | {"ASR ID".PadRight(actionColumnWidth)} | {"Name".PadRight(nameColumnWidth)} |";

            Console.WriteLine(separator);
            Console.WriteLine(header);
            Console.WriteLine(separator);

            foreach (var item in data)
            {
                string row = $"| {item.Item1.PadRight(idColumnWidth)} | {item.Item2.PadRight(actionColumnWidth)} |  {item.Item3.PadRight(nameColumnWidth)} | ";
                Console.WriteLine(row);
            }

            Console.WriteLine(separator);
        }





    }
}
