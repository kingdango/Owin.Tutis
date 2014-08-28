using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Net.Http;

namespace Kingdango.Owin.Tutis
{
	public abstract class OAuth2AuthenticationOptions : AuthenticationOptions
	{
		protected OAuth2AuthenticationOptions(string authenticationType) : base(authenticationType)
		{
			this.Caption = authenticationType;
			this.BackchannelTimeout = TimeSpan.FromSeconds(60);
			this.Scope = string.Empty;
			this.AuthenticationMode = AuthenticationMode.Passive;
		}

		public virtual string ClientId { get; set; }
		public virtual string ClientSecret { get; set; }

		public abstract OAuth2ServerApiSettings ApiSettings { get; set; }

		/// <summary>
		/// Gets or sets the a pinned certificate validator to use to validate the endpoints used
		/// in back channel communications belong to Google.
		/// </summary>
		/// <value>
		/// The pinned certificate validator.
		/// </value>
		/// <remarks>If this property is null then the default certificate checks are performed,
		/// validating the subject name and if the signing chain is a trusted party.</remarks>
		public ICertificateValidator BackchannelCertificateValidator { get; set; }

		/// <summary>
		/// Gets or sets timeout value in milliseconds for back channel communications with Google.
		/// </summary>
		/// <value>
		/// The back channel timeout in milliseconds.
		/// </value>
		public TimeSpan BackchannelTimeout { get; set; }

		/// <summary>
		/// The HttpMessageHandler used to communicate with Google.
		/// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
		/// can be downcast to a WebRequestHandler.
		/// </summary>
		public HttpMessageHandler BackchannelHttpHandler { get; set; }

		/// <summary>
		/// Get or sets the text that the user can display on a sign in user interface.
		/// </summary>
		public string Caption
		{
			get { return Description.Caption; }
			set { Description.Caption = value; }
		}

		/// <summary>
		/// The request path within the application's base path where the user-agent will be returned.
		/// The middleware will process this request when it arrives.
		/// Default value is "/signin-google".
		/// </summary>
		public virtual PathString CallbackPath { get; set; }

		/// <summary>
		/// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
		/// </summary>
		public string SignInAsAuthenticationType { get; set; }

		/// <summary>
		/// Gets or sets the <see cref="IGoogleOAuth2AuthenticationProvider"/> used to handle authentication events.
		/// </summary>
		public OAuth2AuthenticationProvider Provider { get; set; }

		/// <summary>
		/// Gets or sets the type used to secure data handled by the middleware.
		/// </summary>
		public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

		/// <summary>
		/// A list of permissions to request.
		/// </summary>
		public string Scope { get; set; }

		/// <summary>
		/// access_type. Set to 'offline' to request a refresh token.
		/// </summary>
		public string AccessType { get; set; }
	}
}
