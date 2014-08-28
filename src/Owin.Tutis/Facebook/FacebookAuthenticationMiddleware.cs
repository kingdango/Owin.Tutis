using Microsoft.Owin;
using Owin;

namespace Kingdango.Owin.Tutis.Facebook
{
	public class FacebookAuthenticationMiddleware : OAuth2AuthenticationMiddleware<FacebookAuthenticationOptions, FacebookAuthenticationHandler>
	{
		public FacebookAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, FacebookAuthenticationOptions options)
			: base(next, options, app)
		{
		}
	}
}