using Microsoft.Owin;

namespace Kingdango.Owin.Tutis.Facebook
{
	public class FacebookAuthenticationOptions : OAuth2AuthenticationOptions
	{
		private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
		private const string TokenEndpoint = "https://graph.facebook.com/oauth/access_token";
		private const string GraphApiEndpoint = "https://graph.facebook.com/me";
		private const string OAuthEndpoint = "https://www.facebook.com/dialog/oauth";
		public const string FacebookProviderName = "Facebook";

		public virtual string AppId
		{
			get { return ClientId; }
			set { ClientId = value; }
		}

		public virtual string AppSecret
		{
			get { return ClientSecret; }
			set { ClientSecret = value; }
		}

		public override OAuth2ServerApiSettings ApiSettings { get; set; }

		public override PathString CallbackPath {
			get { return new PathString("/signin-facebook"); }
		}

		public FacebookAuthenticationOptions()
			: base(FacebookProviderName)
		{
			this.ApiSettings = new OAuth2ServerApiSettings
			{
				XmlSchemaString = XmlSchemaString,
				GraphApiEndpoint = GraphApiEndpoint,
				TokenEndpoint = TokenEndpoint,
				OAuthEndpoint = OAuthEndpoint
			};
		}
	}
}