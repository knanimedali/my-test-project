// VulnerableApp.cs
// Exemple pédagogique — contient plusieurs vulnérabilités communes en C# / ASP.NET-style.
// NE PAS UTILISER EN PRODUCTION.

using System;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace VulnerableExample
{
    class VulnerableApp
    {
        // === 1) Hardcoded credentials (insecure storage) ===
        // Problème : identifiants en clair dans le code source.
        // Danger : fuite du code => compromission des comptes.
        private static string dbUser = "admin";
        private static string dbPassword = "P@ssw0rd123"; // Hardcoded secret!

        static void Main(string[] args)
        {
            Console.WriteLine("=== Vulnerable C# Example ===");

            Console.Write("Entrez un id d'utilisateur (ex : 1 OR 1=1) : ");
            string id = Console.ReadLine();
            Console.WriteLine(GetUserById(id));

            Console.Write("Entrez commande shell à exécuter : ");
            string cmd = Console.ReadLine();
            ExecuteShell(cmd);

            // Insecure deserialization
            byte[] incoming = GetSerializedDataFromUntrustedSource();
            object obj = DeserializeUntrusted(incoming);
            Console.WriteLine("Objet désérialisé: " + (obj?.ToString() ?? "null"));

            // File upload simulation
            Console.Write("Entrez chemin du fichier à sauvegarder (ex : ../malicious.exe) : ");
            string path = Console.ReadLine();
            SaveUploadedFile(path, new byte[] { 0x0 }); // simulé
        }

        // === 2) SQL Injection via concaténation de chaîne ===
        // Problème : concaténation directe de l'entrée utilisateur dans la requête SQL.
        // Danger : un attaquant peut manipuler la requête (extraction, suppression de données).
        public static string GetUserById(string id)
        {
            // Chaîne de connexion simplifiée (pour l'exemple)
            string connStr = $"Server=localhost;User Id={dbUser};Password={dbPassword};Database=DemoDB;";
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                conn.Open();
                // VULN: interpolation/concaténation — susceptible d'injection SQL
                string query = "SELECT Name, Email FROM Users WHERE Id = " + id;
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    using (SqlDataReader r = cmd.ExecuteReader())
                    {
                        if (r.Read())
                        {
                            return $"Name: {r["Name"]}, Email: {r["Email"]}";
                        }
                        else
                        {
                            return "Aucun utilisateur trouvé.";
                        }
                    }
                }
            }
        }

        // === 3) Command Injection / Execution of arbitrary shell command ===
        // Problème : exécution d'une commande fournie par l'utilisateur sans validation.
        // Danger : exécution de commandes arbitraires.
        public static void ExecuteShell(string command)
        {
            try
            {
                // VULN: Process.Start avec entrée non filtrée
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + command);
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    Console.WriteLine("Sortie commande:\n" + output);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erreur exécution commande: " + ex.Message);
            }
        }

        // === 4) Insecure deserialization ===
        // Problème : utiliser BinaryFormatter sur des données non fiabilisées permet l'exécution de code arbitraire.
        // Danger : désérialisation de payloads malveillants.
        public static object DeserializeUntrusted(byte[] data)
        {
            if (data == null || data.Length == 0)
                return null;

            BinaryFormatter bf = new BinaryFormatter(); // BinaryFormatter est dangereux et obsolète
            using (MemoryStream ms = new MemoryStream(data))
            {
                // VULN: désérialisation de données non fiables
                return bf.Deserialize(ms);
            }
        }

        // Simulation : on "reçoit" des données sérialisées d'une source externe.
        private static byte[] GetSerializedDataFromUntrustedSource()
        {
            // Pour l'exemple on retourne un tableau vide (mais en vrai ce serait du flux non fiable)
            return new byte[0];
        }

        // === 5) Insecure file handling / path traversal ===
        // Problème : sauvegarde de fichiers sans validation du nom/chemin => path traversal possible.
        public static void SaveUploadedFile(string userPath, byte[] content)
        {
            try
            {
                // VULN: utilisation directe du chemin fourni par l'utilisateur
                string saveDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uploads");
                Directory.CreateDirectory(saveDir);
                string finalPath = Path.Combine(saveDir, userPath); // si userPath contient ../ -> sortie du dossier uploads

                File.WriteAllBytes(finalPath, content);
                Console.WriteLine("Fichier sauvegardé dans : " + finalPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erreur sauvegarde fichier: " + ex.Message);
            }
        }
    }
}

