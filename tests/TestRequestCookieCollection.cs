using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class TestRequestCookieCollection : Dictionary<string, string>, IRequestCookieCollection
{
    public TestRequestCookieCollection(Dictionary<string, string> cookies) : base(cookies) { }

    public new ICollection<string> Keys => base.Keys;

    public new string this[string key]
    {
        get
        {
            TryGetValue(key, out var value);
            return value ?? string.Empty;
        }
        set
        {
            base[key] = value;
        }
    }
}
