using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Kingdango.Owin.Tutis
{
	public abstract class OAuth2AuthenticationHandler<T> : AuthenticationHandler<T>
		where T: OAuth2AuthenticationOptions
	{
		public ILogger Logger { get; set; }
		public HttpClient HttpClient { get; set; }

		protected OAuth2AuthenticationHandler()
		{
			
		} 

		protected OAuth2AuthenticationHandler(HttpClient httpClient, ILogger logger)
		{
			HttpClient = httpClient;
			Logger = logger;
		}

		protected abstract override Task<AuthenticationTicket> AuthenticateCoreAsync();
		
		protected override Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode != 401)
			{
				return Task.FromResult<object>(null);
			}

			AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

			if (challenge != null)
			{
				string baseUri =
					Request.Scheme +
					Uri.SchemeDelimiter +
					Request.Host +
					Request.PathBase;

				string currentUri =
					baseUri +
					Request.Path +
					Request.QueryString;

				string redirectUri =
					baseUri +
					Options.CallbackPath;

				AuthenticationProperties properties = challenge.Properties;
				if (string.IsNullOrEmpty(properties.RedirectUri))
				{
					properties.RedirectUri = currentUri;
				}

				// OAuth2 10.12 CSRF
				GenerateCorrelationId(properties);
				
				string state = Options.StateDataFormat.Protect(properties);

				string authorizationEndpoint =
					Options.ApiSettings.OAuthEndpoint +
					"?response_type=code" +
					"&client_id=" + Uri.EscapeDataString(Options.ClientId) +
					"&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
					"&scope=" + Uri.EscapeDataString(Options.Scope) +
					"&state=" + Uri.EscapeDataString(state);

				var redirectContext = new OAuth2ApplyRedirectContext(
					Context, Options,
					properties, authorizationEndpoint);
				Options.Provider.ApplyRedirect(redirectContext);
			}

			return Task.FromResult<object>(null);
		}

		public override async Task<bool> InvokeAsync()
		{
			return await InvokeReplyPathAsync();
		}

		private async Task<bool> InvokeReplyPathAsync()
		{
			if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
			{
				// TODO: error responses

				var ticket = await AuthenticateAsync();
				if (ticket == null)
				{
					Logger.WriteWarning("Invalid return state, unable to redirect.");
					Response.StatusCode = 500;
					return true;
				}

				var context = new OAuth2ReturnEndpointContext(Context, ticket);
				context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
				context.RedirectUri = ticket.Properties.RedirectUri;

				await Options.Provider.ReturnEndpoint(context);

				if (context.SignInAsAuthenticationType != null &&
					context.Identity != null)
				{
					var grantIdentity = context.Identity;
					if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
					{
						grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
					}
					Context.Authentication.SignIn(context.Properties, grantIdentity);
				}

				if (!context.IsRequestCompleted && context.RedirectUri != null)
				{
					var redirectUri = context.RedirectUri;
					if (context.Identity == null)
					{
						// add a redirect hint that sign-in failed in some way
						redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
					}
					Response.Redirect(redirectUri);
					context.RequestCompleted();
				}

				return context.IsRequestCompleted;
			}
			return false;
		}

		protected void LogIfQuerystringContainsError(IReadableStringCollection query)
		{
			IList<string> values = query.GetValues("error");
			if (values != null && values.Count >= 1)
			{
				this.Logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
			}
		}

		protected string GetQuerystringValueOrNull(IReadableStringCollection querystring, string key)
		{
			var values = querystring.GetValues(key);
			return values != null && values.Count == 1 ? values[0] : null;
		}
	}
}