namespace Kingdango.Owin.Tutis.LinkedIn
{
	public class LinkedInAuthenticationOptions : OAuth2AuthenticationOptions
	{
		private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
		private const string TokenEndpoint = "https://www.linkedin.com/uas/oauth2/accessToken";
		private const string UserInfoEndpoint = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,formatted-name,email-address,public-profile-url)";
		private const string AuthEndpoint = "https://www.linkedin.com/uas/oauth2/authorization";

		public const string LinkedInProviderName = "LinkedIn";

		public LinkedInAuthenticationOptions()
			: base(LinkedInProviderName)
		{
			this.ApiSettings = new OAuth2ServerApiSettings
			{
				OAuthEndpoint = AuthEndpoint,
				XmlSchemaString = XmlSchemaString,
				TokenEndpoint = TokenEndpoint,
				GraphApiEndpoint = UserInfoEndpoint
			};
		}

		public override OAuth2ServerApiSettings ApiSettings { get; set; }
	}
}