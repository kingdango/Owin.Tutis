using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Kingdango.Owin.Tutis
{
	public abstract class OAuth2AuthenticationMiddleware<TOptions, THandler> : AuthenticationMiddleware<TOptions>
		where TOptions: OAuth2AuthenticationOptions, new()
		where THandler : OAuth2AuthenticationHandler<TOptions>, new()
	{
		protected readonly HttpClient _httpClient;
		protected readonly ILogger _logger;

		protected OAuth2AuthenticationMiddleware(OwinMiddleware next, TOptions options,
			IAppBuilder app)
			: base(next, options)
		{
			_logger = app.CreateLogger<OAuth2AuthenticationMiddleware<TOptions, THandler>>();

			_httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
			{
				Timeout = Options.BackchannelTimeout,
				MaxResponseContentBufferSize = 1024 * 1024 * 10
			};
			
			if(this.Options.Provider == null)
				this.Options.Provider = new OAuth2AuthenticationProvider();
			
			if (this.Options.StateDataFormat == null)
				this.Options.StateDataFormat = (ISecureDataFormat<AuthenticationProperties>)new PropertiesDataFormat(app.CreateDataProtector(typeof(OAuth2AuthenticationMiddleware<TOptions, THandler>).FullName, this.Options.AuthenticationType, "v1"));
			
			if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
				this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
			
			this._httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options));
			this._httpClient.Timeout = this.Options.BackchannelTimeout;
			this._httpClient.MaxResponseContentBufferSize = 10485760L;
		}

		protected override AuthenticationHandler<TOptions> CreateHandler()
		{
			var handler = new THandler {HttpClient = _httpClient, Logger = _logger};
			return handler;
		}

		private HttpMessageHandler ResolveHttpMessageHandler(TOptions options)
		{
			HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

			// If they provided a validator, apply it or fail.
			if (options.BackchannelCertificateValidator != null)
			{
				// Set the cert validate callback
				var webRequestHandler = handler as WebRequestHandler;
				if (webRequestHandler == null)
				{
					throw new InvalidOperationException("Validator Handler Mismatch");
				}
				webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
			}

			return handler;
		}
	}
}