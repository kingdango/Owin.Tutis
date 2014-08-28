using Owin;
using System;

namespace Kingdango.Owin.Tutis.Facebook
{
	public static class FacebookExtensions
	{
		public static IAppBuilder UseFacebookAuthentication(this IAppBuilder app, FacebookAuthenticationOptions options)
		{
			if (app == null) throw new ArgumentNullException("app");
			if (options == null) throw new ArgumentNullException("options");

			app.Use(typeof(FacebookAuthenticationMiddleware), app, options);

			return app;
		}

		public static IAppBuilder UseFacebookAuthentication(this IAppBuilder app, string appId, string appSecret)
		{
			return UseFacebookAuthentication(
				app,
				new FacebookAuthenticationOptions()
				{
					AppId = appId,
					AppSecret = appSecret,
				});
		}
	}
}
