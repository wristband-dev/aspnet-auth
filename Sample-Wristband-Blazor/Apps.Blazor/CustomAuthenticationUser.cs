namespace Apps.Blazor;

public class CustomAuthenticationUser
{
    public string Name { get; set; }
    public string Email { get; set; }
    public CustomAuthenticationUser(string name, string email)
    {
        Name = name;
        Email = email;
    }
}
