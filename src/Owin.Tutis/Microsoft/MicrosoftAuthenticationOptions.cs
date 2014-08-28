namespace Kingdango.Owin.Tutis.Microsoft
{
	public class MicrosoftAuthenticationOptions : OAuth2AuthenticationOptions
	{
		private const string TokenEndpoint = "https://login.live.com/oauth20_token.srf";
		private const string GraphApiEndpoint = "https://apis.live.net/v5.0/me";
		private const string AuthEndpoint = "https://login.live.com/oauth20_authorize.srf";
		public const string MicrosoftProviderName = "Microsoft";

		public MicrosoftAuthenticationOptions()
			: base(MicrosoftProviderName)
		{
			this.ApiSettings = new OAuth2ServerApiSettings
			{
				TokenEndpoint = TokenEndpoint,
				GraphApiEndpoint = GraphApiEndpoint,
				OAuthEndpoint = AuthEndpoint
			};
		}

		public override OAuth2ServerApiSettings ApiSettings { get; set; }
	}
}