using Microsoft.Owin;

namespace Kingdango.Owin.Tutis.Google
{
	public class GoogleAuthenticationOptions : OAuth2AuthenticationOptions
	{
		private const string TokenEndpoint = "https://accounts.google.com/o/oauth2/token";
		private const string UserInfoEndpoint = "https://www.googleapis.com/plus/v1/people/me";
		private const string AuthorizeEndpoint = "https://accounts.google.com/o/oauth2/auth";
		public const string GoogleProviderName = "Google";

		public GoogleAuthenticationOptions() : base(GoogleProviderName)
		{
			this.ApiSettings = new OAuth2ServerApiSettings
			{
				TokenEndpoint = TokenEndpoint,
				GraphApiEndpoint = UserInfoEndpoint,
				OAuthEndpoint = AuthorizeEndpoint
			};

			this.Scope = "openid profile email"; // Google wants a non-empty scope
		}
		
		public override OAuth2ServerApiSettings ApiSettings { get; set; }

		public override PathString CallbackPath
		{
			get { return new PathString("/signin-google"); }
		}
	}
}