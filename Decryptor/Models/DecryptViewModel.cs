namespace Decryptor.Models
{
    public class UserPasswordResult
    {
        public string UserName { get; set; }
        public string EncryptedPassword { get; set; }
        public string DecryptedPassword { get; set; }
    }

    public class DecryptViewModel
    {
        public string Environment { get; set; }
        public string UserNames { get; set; } // Comma or newline separated input
        public List<UserPasswordResult> Results { get; set; } = new List<UserPasswordResult>();
    }
}
