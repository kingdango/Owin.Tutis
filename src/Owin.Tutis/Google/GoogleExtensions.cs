using Owin;
using System;

namespace Kingdango.Owin.Tutis.Google
{
	public static class GoogleExtensions
	{
		public static IAppBuilder UseGoogleAuthentication(this IAppBuilder app, GoogleAuthenticationOptions options)
		{
			if (app == null) throw new ArgumentNullException("app");
			if (options == null) throw new ArgumentNullException("options");

			app.Use(typeof(GoogleAuthenticationMiddleware), app, options);

			return app;
		}

		public static IAppBuilder UseGoogleAuthentication(this IAppBuilder app, string clientId, string clientSecret)
		{
			return UseGoogleAuthentication(
				app,
				new GoogleAuthenticationOptions()
				{
					ClientId = clientId,
					ClientSecret = clientSecret
				});
		}
	}
}
