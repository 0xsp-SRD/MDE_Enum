using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics.Eventing.Reader;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.RegularExpressions;
using System.Linq;
using MDE_Enum;
using System.Reflection;





namespace WindowsDefenderEventLog_Enum
{
    class Program
    {
        static void QueryAsrRules(string computerName, string domain, string username, string password)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (username != null && password != null)
                {
                    options.Username = username;
                    options.Password = password;
                    options.Impersonation = ImpersonationLevel.Impersonate;
                }

                string scopePath = $"\\\\{computerName}\\root\\Microsoft\\Windows\\Defender";
                ManagementScope scope = new ManagementScope(scopePath, options);
                scope.Connect();

                ObjectQuery query = new ObjectQuery("SELECT * FROM MSFT_MpPreference");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();

                foreach (ManagementObject m in queryCollection)
                {
                    var asrRulesActions = m["AttackSurfaceReductionRules_Actions"] as byte[]; 
                    var asrRulesGuids = m["AttackSurfaceReductionRules_Ids"] as string[]; 
                 //   var asrRulesNames = m["ASRRules_Names"];

                   


                    var AsrRData = new List<Tuple<string,string,string >> (); 

                    if (asrRulesActions != null)
                    {
                       string[] actions = (asrRulesActions as byte[])?.Select(b => b.ToString("X2")).ToArray();
                       string[] guids = asrRulesGuids; 
                      // string[] names = (string[])asrRulesNames;
                    


                        for (int i = 0; i < actions.Length; i++)
                        {

                            string id = guids[i].ToUpper(); 
                            string names = funcs.AsrRuleDescriptions.ContainsKey(id.ToUpper()) ? funcs.AsrRuleDescriptions[id.ToUpper()] : "Unknown ASR Rule"; // this will check if the ID matches the name 
                            AsrRData.Add(new Tuple<string, string, string>(actions[i], id, names));
                        }
                    }
                    funcs.PrintTable(AsrRData);

                }
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("UnauthorizedAccessException: " + e.Message);
                Console.WriteLine("Ensure you run the application with sufficient permissions.");
            }
            catch (ManagementException e)
            {
                Console.WriteLine("ManagementException: " + e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("An unexpected error occurred: " + e.Message);
            }
        }


        static void Main(string[] args) 
        {
            if (args.Length == 2 && args[0].ToLower() == "/local" && args[1].ToLower() == "/paths")
            {
                QueryLocal("/paths");
            }

            else if (args.Length == 3 && args[0].ToLower() == "/local" && args[1].ToLower() == "/paths" && args[2].ToLower() == "/access")
            {
                QueryLocal("/paths AND Check");
            }

            else if (args.Length == 3 && args[0].ToLower() == "/local" && args[1].ToLower() == "/asr" && args[2].ToLower() == "/alt")
            {
                Console.WriteLine("[+] Enumerating ASR Rules on Local System"); 

                QueryAsrRules("localhost", null, null, null); 

            }
            else if (args.Length == 6 && args[4].ToLower() == "/asr" && args[5].ToLower() == "/alt")
            {

                Console.WriteLine($@"[+] Enumerating ASR Rules on Remote System {args[0]} "); 
                QueryAsrRules(args[0], args[1], args[2], args[3]);

            }

            else if (args.Length == 2 && args[0].ToLower() == "/local" && args[1].ToLower() == "/asr")
            {
                QueryLocal("/Asr");
            }
            else if (args.Length == 5)
            {
                QueryRemote(args);
            }

            else
            {
                funcs.Banner();
            }
        }

        static void QueryLocal(string mode)

        // https://x.com/VakninHai/status/1796628601535652289

        {
            Console.WriteLine($@"
      ----------------------------------------

      [!] Type : Local System Enumeration 
      [!] Mode: {mode} Events 
      ----------------------------------------

");
            int eventId = 0;
            bool CheckAccessMode = false; 

            if (mode == "/paths") {
                 eventId = 5007;
            } else if (mode == "/asr")
            {
                eventId = 1121; 
            }   
            else if ( mode == "/paths AND Check")
            {
                eventId = 5007; 
                CheckAccessMode = true; 

            }





            string pattern = @"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\(.*)";

            string logName = "Microsoft-Windows-Windows Defender/Operational";





            EventLogQuery query = new EventLogQuery(logName, PathType.LogName, $"*[System/EventID={eventId}]");

            try
            {
                EventLogReader reader = new EventLogReader(query);

                for (EventRecord eventInstance = reader.ReadEvent(); eventInstance != null; eventInstance = reader.ReadEvent())
                {


                 
                    string message = eventInstance.FormatDescription();




                    if (eventId == 1121)
                    {
                        string asrRuleId = funcs.ExtractAsrRuleId(message);


                        if (!string.IsNullOrEmpty(asrRuleId) && funcs.AsrRuleDescriptions.TryGetValue(asrRuleId, out string ruleDescription))
                        {
                            Console.WriteLine($"[+] ASR Rule Triggered: {ruleDescription} -  ({asrRuleId})");
                            Console.WriteLine(" [!] Time Created: " + eventInstance.TimeCreated);
                            Console.WriteLine();
                        }


                    } 
                    else if (eventId == 5007)
                    {

                        Match match = Regex.Match(message, pattern);


                        if (match.Success)
                        {
                            string found = match.Groups[1].Value;

                            found = found.Split(' ')[0]; // this will remove 0x0  


                            Console.WriteLine("[+] Exclusion Path: " + found);
                            Console.WriteLine("[!] Time Created: " + eventInstance.TimeCreated);

                     
                            // check if discovered paths are writable 
                            if (CheckAccessMode == true)
                            {
                                bool Access = funcs.CheckWriteAccess(found);

                                if (Access == true)
                                {
                                    Console.WriteLine("[+] Write Access: True ");
                                }
                                else
                                {
                                    Console.WriteLine("[+] Write Access: False ");
                                }
                                Console.WriteLine();

                            }
                        }

                    }
                }
            }
            catch (EventLogException e)
            {
                Console.WriteLine("An error occurred: " + e.Message);
            }
        }


        static void QueryRemote(string[] args)
        {

            string remoteComputer = args[0];
            string username = args[1];
            string password = args[2];
            string domain = args[3];
            string mode = args[4];

            int eventId = 0; 
            

            if ( mode == "/paths")
            {
                eventId = 5007;
            }
            else if ( mode == "/asr")
            {
                eventId = 1121; 
            
            }
            else
            {
                Console.WriteLine("Usage: WindowsDefenderEventLog_Enum <remoteComputer> <username> <password> <domain> /asr");
                Console.WriteLine("       WindowsDefenderEventLog_Enum <remoteComputer> <username> <password> <domain> /paths");

            }

            Console.WriteLine($@"

      ----------------------------------------
      [+] Authenticating to : {args[0]} 
      [!] Type : Remote Computer Enumeration 
      [!] Mode : {mode}  
      ----------------------------------------
    

");



            string pattern = @"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\(.*)";

            SecureString securePassword = funcs.ConvertToSecureString(password);

             

            // https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession?view=net-8.0

            EventLogSession session = new EventLogSession(remoteComputer, domain, username, securePassword, SessionAuthentication.Default);
            string logName = "Microsoft-Windows-Windows Defender/Operational";

            EventLogQuery query = new EventLogQuery(logName, PathType.LogName, $"*[System/EventID={eventId}]")
            {
                Session = session
            };

            try
            {
                EventLogReader reader = new EventLogReader(query);

                for (EventRecord eventInstance = reader.ReadEvent(); eventInstance != null; eventInstance = reader.ReadEvent())
                {
                    string message = eventInstance.FormatDescription();



                    if (eventId == 1121)
                    {
                        string asrRuleId = funcs.ExtractAsrRuleId(message);


                        if (!string.IsNullOrEmpty(asrRuleId) && funcs.AsrRuleDescriptions.TryGetValue(asrRuleId, out string ruleDescription))
                        {
                            Console.WriteLine($"[+] ASR Rule Triggered: {ruleDescription} -  ({asrRuleId})");
                            Console.WriteLine(" [!] Time Created: " + eventInstance.TimeCreated);
                            Console.WriteLine();
                        }


                    }
                    else if (eventId == 5007)
                    {



                        Match match = Regex.Match(message, pattern);
                        if (match.Success)
                        {
                            string found = match.Groups[1].Value;
                            Console.WriteLine("[+] Exclusion Path: " + found);
                            Console.WriteLine("[i] Time Created: " + eventInstance.TimeCreated);
                            Console.WriteLine();
                        }
                    }
                }
            }
            catch (EventLogException e)
            {
                Console.WriteLine("An error occurred: " + e.Message);
            }
        }

       
    }
}
