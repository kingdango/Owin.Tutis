using Microsoft.Owin;
using Owin;

namespace Kingdango.Owin.Tutis.Google
{
	public class GoogleAuthenticationMiddleware : OAuth2AuthenticationMiddleware<GoogleAuthenticationOptions, GoogleAuthenticationHandler>
	{
		public GoogleAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, GoogleAuthenticationOptions options)
			: base(next, options, app)
		{
		}
	}
}