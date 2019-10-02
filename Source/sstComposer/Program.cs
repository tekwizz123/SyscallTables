/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2019
*
*  TITLE:       PROGRAM.CS
*
*  VERSION:     1.20
*
*  DATE:        02 Oct 2019
*
*  SSTC entrypoint.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace sstc
{
    public class sstTable
    {
        public int[] Indexes;
        public string ServiceName;
    }

    class Program
    {
        static int IndexOfItem(string ServiceName, List<sstTable> DataItems)
        {
            for (int i = 0; i < DataItems.Count; i++)
            {
                var Entry = DataItems[i];
                if (Entry.ServiceName == ServiceName)
                    return i;
            }
            return -1;
        }

        public class ItemsComparer : IComparer
        {
            public int Compare(Object x, Object y)
            {
                int a = Convert.ToInt32(Path.GetFileNameWithoutExtension(x as string));
                int b = Convert.ToInt32(Path.GetFileNameWithoutExtension(y as string));

                if (a == b)
                    return 0;

                if (a > b)
                    return 1;
                else
                    return -1;
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                System.Console.WriteLine("Please enter a type of generated report.");
                System.Console.WriteLine("Usage: sstc -m | -h [-w]");
                System.Console.ReadKey();
                return;
            }

            string opt = "";
            string cmd = args[0];
            if (args.Length > 1)
            {
                opt = args[1];
            }
            if (cmd != "-m" && cmd != "-h")
            {
                System.Console.WriteLine("Invalid report type key, supported types keys are markdown [-m] and html [-h].");
                System.Console.ReadKey();
                return;
            }

            string LookupDirectory = Directory.GetCurrentDirectory() + "\\tables\\";

            if (opt != "-w")
            {
                LookupDirectory += "ntos\\";
            }
            else
            {
                LookupDirectory += "win32k\\";
            }

            string[] Tables;

            try
            {
                Tables = Directory.GetFiles(LookupDirectory, "*.txt");
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.Message);
                return;
            }

            IComparer Comparer = new ItemsComparer();
            Array.Sort(Tables, Comparer);

            int fcount = Tables.Count();
            int count = 0;

            List<sstTable> DataItems = new List<sstTable>();
            int n = 0, id;

            //
            // Makrdown header.
            //

            string MarkdownHeader = "| # | ServiceName |";
            string MarkdownSubHeader = "| --- | --- | ";

            //
            // Parse files into internal array.
            //

            foreach (var sName in Tables)
            {
                string[] fData;
                MarkdownHeader += (Path.GetFileNameWithoutExtension(sName) + " | ");

                try
                {
                    fData = File.ReadAllLines(sName);
                    for (int i = 0; i < fData.Count(); i++)
                    {
                        int u = 0;
                        int syscall_id;
                        string syscall_name;

                        u = fData[i].IndexOf('\t') + 1;

                        syscall_id = Convert.ToInt32(fData[i].Substring(u));
                        syscall_name = fData[i].Substring(0, u - 1);

                        id = IndexOfItem(syscall_name, DataItems);
                        if (id != -1)
                        {
                            var sstEntry = DataItems[id];
                            sstEntry.Indexes[n] = syscall_id;
                        }
                        else
                        {
                            var sstEntry = new sstTable();
                            sstEntry.ServiceName = syscall_name;
                            sstEntry.Indexes = new int[fcount];
                            for (int k = 0; k < fcount; k++)
                                sstEntry.Indexes[k] = -1;
                            sstEntry.Indexes[n] = syscall_id;
                            DataItems.Add(sstEntry);
                        }
                    }

                }
                catch (Exception e)
                {
                    System.Console.WriteLine(e.Message);
                }
                n++;
                MarkdownSubHeader += (" --- | ");
            }

            StreamWriter file;

            try
            {
                if (cmd == "-m")
                {
                    if (opt != "-w")
                    {
                        file = new StreamWriter("syscalls.md", false, Encoding.UTF8);
                    }
                    else
                    {
                        file = new StreamWriter("w32ksyscalls.md", false, Encoding.UTF8);
                    }

                    file.WriteLine(MarkdownHeader);
                    file.WriteLine(MarkdownSubHeader);

                    foreach (var Entry in DataItems)
                    {
                        count += 1;

                        var s = "| " + count.ToString("0000") + " | ";
                        s += Entry.ServiceName + " | ";

                        for (int i = 0; i < fcount; i++)
                        {
                            if (Entry.Indexes[i] != -1)
                            {
                                s += Entry.Indexes[i].ToString() + " | ";
                            }
                            else
                            {
                                s += "  | ";
                            }
                        }
                        file.WriteLine(s);
                    }
                    file.Close();

                }

                if (cmd == "-h")
                {
                    string ReportHead = "<!DOCTYPE html><html><head>" +
                                        "<style>" +
                                        "table, th, td {" +
                                        "border: 1px solid black;" +
                                        "border-collapse: collapse;" +
                                        "} th, td {" +
                                        "padding: 5px;" +
                                        "} table tr:nth-child(even) { background-color: #eee;}" +
                                        "table tr:nth-child(odd) { background-color:#fff;}" +
                                        "table th { background-color: white; color: black; }" +
                                        "</style></head><body>";

                    string ColStart = "<td>";
                    string ColEnd = "</td>";
                    string RowEnd = "</tr>";

                    string ReportEnd = "</table></body></html>";
                    string TableHead = "<table><caption>Syscall Table Indexes</caption>" +
                    "<tr><th style=\"width:20px\">#</th>" +
                    "<th style=\"width:130px\">ServiceName</th>";

                    for (int i = 0; i < fcount; i++)
                    {
                        TableHead += "<th style=\"width:40px\">" +
                            Path.GetFileNameWithoutExtension(Tables[i]) + "</th>";

                    }
                    TableHead += RowEnd;

                    string item = "";

                    if (opt != "-w")
                    {
                        file = new StreamWriter("syscalls.html", false, Encoding.UTF8);
                    }
                    else
                    {
                        file = new StreamWriter("w32ksyscalls.html", false, Encoding.UTF8);
                    }
                    file.WriteLine(ReportHead);
                    file.WriteLine(TableHead);

                    for (int i = 0; i < DataItems.Count; i++)
                    {
                        var Entry = DataItems[i];

                        item += "<tr><td>" + (i + 1).ToString() + ColEnd;
                        item += ColStart + Entry.ServiceName + ColEnd;

                        for (int j = 0; j < fcount; j++)
                        {
                            item += ColStart;
                            if (Entry.Indexes[j] != -1)
                            {
                                item += Entry.Indexes[j].ToString();
                            }
                            else
                            {
                                item += " ";
                            }
                            item += ColEnd;
                        }
                        item += RowEnd;
                    }
                    file.WriteLine(item);
                    file.WriteLine(ReportEnd);
                    file.Close();
                } // cmd == -h

            } //try
            catch (Exception e)
            {
                System.Console.WriteLine(e.Message);
                System.Console.ReadKey();
            }
        }
    }
}
