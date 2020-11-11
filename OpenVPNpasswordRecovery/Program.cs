using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenVPNpasswordRecovery
{
    class Program
    {
        static void Main(string[] args)
        {
            RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\OpenVPN-GUI\configs");
            foreach (string rkconf in rk.GetSubKeyNames())
            {
                using (RegistryKey tempKey = rk.OpenSubKey(rkconf))
                {
                    byte[] Data = (byte[])tempKey.GetValue("auth-data", tempKey.GetValue("key-data"));
                    byte[] Entropy = (byte[])tempKey.GetValue("entropy");
                    byte[] destropy = new byte[(Entropy.Length) - 1];
                    Array.Copy(Entropy, destropy, Entropy.Length - 1);

                    string[] t = tempKey.Name.Split('\\'); Array.Reverse(t);
                    string tName = t[0];

                    byte[] password = System.Security.Cryptography.ProtectedData.Unprotect(Data, destropy, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                    Console.WriteLine("{0} = {1}", tName, System.Text.Encoding.Unicode.GetString(password));

                }

            }
            Console.ReadKey();

        }
    }
}
