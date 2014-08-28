using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Kingdango.Owin.Tutis
{
	public class OAuth2ApplyRedirectContext : BaseContext<OAuth2AuthenticationOptions>
	{
		public OAuth2ApplyRedirectContext(IOwinContext context, OAuth2AuthenticationOptions options,
			AuthenticationProperties properties, string redirectUri) : base(context, options)
		{
			RedirectUri = redirectUri;
			Properties = properties;
		}

		public string RedirectUri { get; private set; }

		public AuthenticationProperties Properties { get; private set; }
	}
}