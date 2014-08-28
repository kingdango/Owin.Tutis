using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Kingdango.Owin.Tutis.Microsoft
{
	public class MicrosoftAuthenticationMiddleware : OAuth2AuthenticationMiddleware<MicrosoftAuthenticationOptions, MicrosoftAuthenticationHandler>
	{
		public MicrosoftAuthenticationMiddleware(OwinMiddleware next, MicrosoftAuthenticationOptions options, IAppBuilder app) : base(next, options, app)
		{
		}
	}
}