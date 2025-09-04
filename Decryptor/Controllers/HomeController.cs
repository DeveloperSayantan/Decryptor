using Decryptor.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Decryptor.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View(new DecryptViewModel());
        }

        [HttpPost]
        public IActionResult Index(DecryptViewModel model)
        {
            if (!string.IsNullOrEmpty(model.EncryptedPassword))
            {
                try
                {
                    model.DecryptedPassword = Decrypt(model.EncryptedPassword);
                }
                catch (Exception ex)
                {
                    model.DecryptedPassword = $"Error: {ex.Message}";
                }
            }
            return View(model);
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
