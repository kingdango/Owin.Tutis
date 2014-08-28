using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Owin;
using Newtonsoft.Json.Linq;
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