namespace Kingdango.Owin.Tutis
{
	public interface IOAuth2ServerApiSettings
	{
		string XmlSchemaString { get; }
		string TokenEndpoint { get; }
		string GraphApiEndpoint { get; }
		string OAuthEndpoint { get; }
	}

	public class OAuth2ServerApiSettings : IOAuth2ServerApiSettings
	{
		public string XmlSchemaString { get; set; }
		public string TokenEndpoint { get; set; }
		public string GraphApiEndpoint { get; set; }
		public string OAuthEndpoint { get; set; }
	}
}