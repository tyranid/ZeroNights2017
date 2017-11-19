//    This file is part of Zero Nights 2017 UAC Bypass Releases
//    Copyright (C) James Forshaw 2017
//
//    UAC Bypasses is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    UAC Bypasses is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with UAC Bypasses.  If not, see <http://www.gnu.org/licenses/>.

// This program is for use with bypass_uac_capability_auth.ps1 to demonstrate
// impersonating an OTS elevated domain user accessing a web server with 
// authentication.
// To use create a directory called c:\test and make it accessible to the
// ALL_APPLICATION_PACKAGES group. Copy ots_auth.exe into that directory. Then
// modify $url parameter to point to a domain resource with authentication and
// elevate using OTS.

using System;
using System.Net;

namespace WebTest
{
    class Program
    {
        public static void WebTest(string url)
        {
            Console.WriteLine("Opening {0}", url);
            WebClient client = new WebClient
            {
                UseDefaultCredentials = true
            };
            byte[] data = client.DownloadData(url);
            Console.WriteLine("Opened URL successfully, Content-Length {0}", data.Length);
        }

        static void Main(string[] args)
        {
            try
            {
                WebTest(args[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.ReadLine();
        }
    }
}
