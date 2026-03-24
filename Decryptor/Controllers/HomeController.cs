using Decryptor.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace Decryptor.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;

        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View(new DecryptViewModel());
        }

        [HttpPost]
        public IActionResult Index(DecryptViewModel model, string actionType)
        {
            if (string.IsNullOrEmpty(model.Environment))
            {
                ModelState.AddModelError("Environment", "Please select an environment");
                return View(model);
            }

            var users = model.UserNames?
                .Split(new[] { ',', '\n', '\r', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(u => u.Trim())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct()
                .ToList();

            if (users == null || !users.Any())
            {
                ModelState.AddModelError("UserNames", "Please enter at least one username");
                return View(model);
            }

            try
            {
                if (actionType == "get")
                {
                    model.Results = GetUserPasswords(model.Environment, users);
                }
                else if (actionType == "duplicate")
                {
                    model.DuplicateResults = GetDuplicateUsers(model.Environment, users);
                }
            }
            catch (Exception ex)
            {
                model.Error = $"Error: {ex.Message}";
            }

            return View(model);
        }

        private string GetConnectionString(string environment)
        {
            return _configuration.GetConnectionString(environment)
                ?? throw new Exception("Invalid environment selection.");
        }

        private List<UserPasswordResult> GetUserPasswords(string environment, List<string> users)
        {
            var results = new List<UserPasswordResult>();
            string connectionString = GetConnectionString(environment);

            using SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();

            foreach (var user in users)
            {
                string query = "SELECT password, full_name, email, is_active, created_on FROM [Security].[login_user] WHERE user_name = @userName";
                using SqlCommand cmd = new SqlCommand(query, conn);
                cmd.Parameters.AddWithValue("@userName", user);

                using SqlDataReader reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string encrypted = reader["password"].ToString();
                    string decrypted = !string.IsNullOrEmpty(encrypted) ? Decrypt(encrypted) : "";

                    results.Add(new UserPasswordResult
                    {
                        UserName = user,
                        FullName = reader["full_name"]?.ToString() ?? "-",
                        Email = reader["email"]?.ToString() ?? "-",
                        IsActive = reader["is_active"] != DBNull.Value && Convert.ToBoolean(reader["is_active"]),
                        CreatedOn = reader["created_on"] != DBNull.Value ? Convert.ToDateTime(reader["created_on"]) : null,
                        EncryptedPassword = encrypted ?? "Not Found",
                        DecryptedPassword = decrypted ?? "-"
                    });
                }
                else
                {
                    results.Add(new UserPasswordResult
                    {
                        UserName = user,
                        FullName = "-",
                        Email = "-",
                        IsActive = false,
                        CreatedOn = null,
                        EncryptedPassword = "NOT FOUND",
                        DecryptedPassword = "-"
                    });
                }
            }

            return results;
        }

        private List<DuplicateUserGroup> GetDuplicateUsers(string environment, List<string> users)
        {
            var duplicateGroups = new List<DuplicateUserGroup>();
            string connectionString = GetConnectionString(environment);

            using SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();

            string userList = string.Join(",", users.Select(u => $"'{u.Replace("'", "''")}'"));
            string query = $@"
        SELECT 
            id,
            user_name,
            password,
            full_name,
            email,
            is_active,
            is_loggedin,
            browser_info,
            is_Password_Updated,
            password_Modified_on,
            created_on
        FROM [Security].[login_user]
        WHERE user_name IN ({userList})
        ORDER BY user_name, created_on";

            using SqlCommand cmd = new SqlCommand(query, conn);
            using SqlDataReader reader = cmd.ExecuteReader();

            var userGroups = new Dictionary<string, List<UserPasswordResult>>();

            while (reader.Read())
            {
                string username = reader["user_name"].ToString();
                string encrypted = reader["password"].ToString();
                string decrypted = !string.IsNullOrEmpty(encrypted) ? Decrypt(encrypted) : "*** DECRYPTION FAILED ***";

                var userResult = new UserPasswordResult
                {
                    UserName = username,
                    FullName = reader["full_name"]?.ToString() ?? "-",
                    Email = reader["email"]?.ToString() ?? "-",
                    IsActive = reader["is_active"] != DBNull.Value && Convert.ToBoolean(reader["is_active"]),
                    IsLoggedin = reader["is_loggedin"] != DBNull.Value && Convert.ToBoolean(reader["is_loggedin"]),
                    BrowserInfo = reader["browser_info"]?.ToString(),
                    IsPasswordModified = reader["is_Password_Updated"] != DBNull.Value && Convert.ToBoolean(reader["is_Password_Updated"]),
                    PasswordModifiedOn = reader["password_Modified_on"] != DBNull.Value ? Convert.ToDateTime(reader["password_Modified_on"]) : null,
                    CreatedOn = reader["created_on"] != DBNull.Value ? Convert.ToDateTime(reader["created_on"]) : null,
                    EncryptedPassword = encrypted,
                    DecryptedPassword = decrypted,
                    Id = Guid.TryParse(reader["id"].ToString(), out Guid id) ? id : Guid.Empty
                };

                if (!userGroups.ContainsKey(username))
                    userGroups[username] = new List<UserPasswordResult>();

                userGroups[username].Add(userResult);
            }

            foreach (var group in userGroups)
            {
                duplicateGroups.Add(new DuplicateUserGroup
                {
                    UserName = group.Key,
                    DuplicateCount = group.Value.Count,
                    Users = group.Value
                });
            }

            foreach (var inputUser in users)
            {
                if (!userGroups.ContainsKey(inputUser))
                {
                    duplicateGroups.Add(new DuplicateUserGroup
                    {
                        UserName = inputUser,
                        DuplicateCount = 0,
                        Users = new List<UserPasswordResult>()
                    });
                }
            }

            return duplicateGroups;
        }

        private string Decrypt(string cipherText)
        {
            byte[] array = Convert.FromBase64String(cipherText);

            using Aes aes = Aes.Create();
            var rfc = new Rfc2898DeriveBytes(
                "CAGSI2021",
                new byte[13] { 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118 }
            );

            aes.Key = rfc.GetBytes(32);
            aes.IV = rfc.GetBytes(16);

            using MemoryStream memoryStream = new MemoryStream();
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(array, 0, array.Length);
                cryptoStream.Close();
            }

            return Encoding.Unicode.GetString(memoryStream.ToArray());
        }
    }
}