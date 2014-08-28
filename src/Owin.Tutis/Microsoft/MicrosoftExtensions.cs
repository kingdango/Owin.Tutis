using Owin;
using System;

namespace Kingdango.Owin.Tutis.Microsoft
{
	public static class MicrosoftExtensions
	{
		public static IAppBuilder UseMicrosoftAuthentication(this IAppBuilder app, MicrosoftAuthenticationOptions options)
		{
			if (app == null) throw new ArgumentNullException("app");
			if (options == null) throw new ArgumentNullException("options");

			app.Use(typeof(MicrosoftAuthenticationMiddleware), app, options);

			return app;
		}

		public static IAppBuilder UseMicrosoftAuthentication(this IAppBuilder app, string clientId, string clientSecret)
		{
			return UseMicrosoftAuthentication(
				app,
				new MicrosoftAuthenticationOptions()
				{
					ClientId = clientId,
					ClientSecret = clientSecret
				});
		}
	}
}