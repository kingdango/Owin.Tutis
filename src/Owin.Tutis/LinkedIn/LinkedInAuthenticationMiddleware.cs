using Microsoft.Owin;
using Owin;

namespace Kingdango.Owin.Tutis.LinkedIn
{
	public class LinkedInAuthenticationMiddleware : OAuth2AuthenticationMiddleware<LinkedInAuthenticationOptions, LinkedInAuthenticationHandler>
	{
		public LinkedInAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, LinkedInAuthenticationOptions options) : base(next, options, app)
		{
		}
	}
}