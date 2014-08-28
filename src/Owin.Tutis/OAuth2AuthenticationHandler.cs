using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
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

		//protected async Task<OAuth2AuthenticationResponse> GetOAuth2Result()
		//{
		//	AuthenticationProperties properties = null;

		//	string code = null;
		//	string state = null;

		//	IReadableStringCollection query = Request.Query;

		//	IList<string> values = query.GetValues("error");
		//	if (values != null && values.Count >= 1)
		//	{
		//		Logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
		//	}

		//	values = query.GetValues("code");
		//	if (values != null && values.Count == 1)
		//	{
		//		code = values[0];
		//	}
		//	values = query.GetValues("state");
		//	if (values != null && values.Count == 1)
		//	{
		//		state = values[0];
		//	}

		//	properties = Options.StateDataFormat.Unprotect(state);
		//	if (properties == null)
		//	{
		//		return null;
		//	}

		//	// OAuth2 10.12 CSRF
		//	if (!ValidateCorrelationId(properties, Logger))
		//	{
		//		return new OAuth2AuthenticationResponse
		//		{
		//			Properties = properties
		//		};
		//	}

		//	if (code == null)
		//	{
		//		// Null if the remote server returns an error.
		//		return new OAuth2AuthenticationResponse
		//		{
		//			Properties = properties
		//		};
		//	}

		//	string requestPrefix = Request.Scheme + "://" + Request.Host;
		//	string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

		//	string tokenRequest = "grant_type=authorization_code" +
		//						  "&code=" + Uri.EscapeDataString(code) +
		//						  "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
		//						  "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
		//						  "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret);

		//	HttpResponseMessage tokenResponse = await HttpClient.GetAsync(Options.ApiSettings.TokenEndpoint + "?" + tokenRequest, Request.CallCancelled);
		//	tokenResponse.EnsureSuccessStatusCode();
		//	string text = await tokenResponse.Content.ReadAsStringAsync();
		//	IFormCollection form = WebHelpers.ParseForm(text);

		//	string accessToken = form["access_token"];
		//	string expires = form["expires"];
		//	string refreshToken = form["refresh_token"];

		//	HttpResponseMessage graphResponse = await HttpClient.GetAsync(
		//		Options.ApiSettings.GraphApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
		//	graphResponse.EnsureSuccessStatusCode();
		//	text = await graphResponse.Content.ReadAsStringAsync();
		//	JObject user = JObject.Parse(text);

		//	return new OAuth2AuthenticationResponse
		//	{
		//		AccessToken = accessToken,
		//		Context = Context,
		//		Expires = expires,
		//		User = user,
		//		Properties = properties,
		//		RefreshToken = refreshToken
		//	};
		//}

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

				AuthenticationTicket ticket = await AuthenticateAsync();
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
					ClaimsIdentity grantIdentity = context.Identity;
					if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
					{
						grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
					}
					Context.Authentication.SignIn(context.Properties, grantIdentity);
				}

				if (!context.IsRequestCompleted && context.RedirectUri != null)
				{
					string redirectUri = context.RedirectUri;
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