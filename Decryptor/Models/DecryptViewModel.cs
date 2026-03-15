namespace Decryptor.Models
{
    public class UserPasswordResult
    {
        public Guid Id { get; set; }
        public string UserName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public bool IsActive { get; set; }
        public bool IsLoggedin { get; set; }
        public string BrowserInfo { get; set; }
        public bool IsPasswordModified { get; set; }
        public DateTime? PasswordModifiedOn { get; set; }   
        public DateTime? CreatedOn { get; set; }
        public string EncryptedPassword { get; set; }
        public string DecryptedPassword { get; set; }
        public string Status => IsActive ? "Active" : "Inactive";
        public string loggedIn => IsLoggedin ? "User Already LoggedIn" : "Not LoggedIn Yet";
        public string passwordModified => IsPasswordModified ? "Yes" : "No";
        public string StatusColor => IsActive ? "success" : "danger";
        public string CreatedOnFormatted => CreatedOn?.ToString("yyyy-MM-dd HH:mm") ?? "-";
    }

    public class DuplicateUserGroup
    {
        public string UserName { get; set; }
        public int DuplicateCount { get; set; }
        public List<UserPasswordResult> Users { get; set; }
    }

    public class DecryptViewModel
    {
        public string Environment { get; set; }
        public string UserNames { get; set; }
        public List<UserPasswordResult> Results { get; set; } = new List<UserPasswordResult>();
        public List<DuplicateUserGroup> DuplicateResults { get; set; } = new List<DuplicateUserGroup>();
        public string Error { get; set; }
        public bool HasResults => Results != null && Results.Any();
        public bool HasDuplicateResults => DuplicateResults != null && DuplicateResults.Any();
    }
}