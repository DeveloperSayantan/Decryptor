using Decryptor.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace Decryptor.Controllers
{
    public class HomeController : Controller
    {
        private readonly Dictionary<string, string> _connectionStrings = new()
        {
            {
                "QA",
                "Server=10.48.16.236;Database=Survey_Core_DB_New;User Id=sa;Password=nF5dK8sY3bQ2tG6rH7jL1zM4;Trusted_Connection=false;MultipleActiveResultSets=true;Encrypt=False;"
            },
            {
                "Stage",
                "Server=10.48.16.236;Database=Health_Core_DB_Stage;User Id=sa;Password=nF5dK8sY3bQ2tG6rH7jL1zM4;Trusted_Connection=false;MultipleActiveResultSets=true;Encrypt=False;"
            },
            {
                "Prod",
                "Server=10.48.16.234;Database=Survey_Core_DB_V2;User Id=read_only_user;Password=sql$developer#95641;Trusted_Connection=false;MultipleActiveResultSets=true;Encrypt=False;"
            }
        };

        public IActionResult Index()
        {
            return View(new DecryptViewModel());
        }

        [HttpPost]
        public IActionResult Index(DecryptViewModel model, string actionType)
        {
            if (actionType == "get" && !string.IsNullOrEmpty(model.UserNames))
            {
                try
                {
                    var users = model.UserNames
                        .Split(new[] { ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(u => u.Trim())
                        .Distinct()
                        .ToList();

                    foreach (var user in users)
                    {
                        var encrypted = GetEncryptedPassword(model.Environment, user);
                        var decrypted = string.Empty;

                        if (!string.IsNullOrEmpty(encrypted))
                        {
                            try
                            {
                                decrypted = Decrypt(encrypted);
                            }
                            catch
                            {
                                decrypted = "Decryption failed";
                            }
                        }

                        model.Results.Add(new UserPasswordResult
                        {
                            UserName = user,
                            EncryptedPassword = encrypted ?? "Not Found",
                            DecryptedPassword = decrypted ?? "-"
                        });
                    }
                }
                catch (Exception ex)
                {
                    model.Results.Add(new UserPasswordResult
                    {
                        UserName = "Error",
                        EncryptedPassword = ex.Message,
                        DecryptedPassword = ""
                    });
                }
            }

            return View(model);
        }

        private string GetEncryptedPassword(string environment, string username)
        {
            if (!_connectionStrings.ContainsKey(environment))
                throw new Exception("Invalid environment selection.");

            string connectionString = _connectionStrings[environment];
            string encryptedPassword = null;

            using SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();

            string query = "SELECT password FROM [Security].[login_user] WHERE user_name = @userName";
            using SqlCommand cmd = new SqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@userName", username);

            var result = cmd.ExecuteScalar();
            if (result != null)
                encryptedPassword = result.ToString();

            return encryptedPassword;
        }

        private string Decrypt(string cipherText)
        {
            byte[] array = Convert.FromBase64String(cipherText);

            using Aes aes = Aes.Create();
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(
                "CAGSI2021",
                new byte[13] { 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118 } // "Ivan Medvedev"
            );

            aes.Key = rfc2898DeriveBytes.GetBytes(32);
            aes.IV = rfc2898DeriveBytes.GetBytes(16);

            using MemoryStream memoryStream = new MemoryStream();
            using (CryptoStream cryptoStream = new CryptoStream(
                memoryStream,
                aes.CreateDecryptor(),
                CryptoStreamMode.Write))
            {
                cryptoStream.Write(array, 0, array.Length);
                cryptoStream.Close();
            }

            return Encoding.Unicode.GetString(memoryStream.ToArray());
        }
    }
}
