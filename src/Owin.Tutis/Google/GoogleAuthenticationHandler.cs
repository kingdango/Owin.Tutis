using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Kingdango.Owin.Tutis.Google
{
	public class GoogleAuthenticationHandler : OAuth2AuthenticationHandler<GoogleAuthenticationOptions>
	{
		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;

			try
			{
				var query = Request.Query;

				LogIfQuerystringContainsError(query);

				var code = GetQuerystringValueOrNull(query, "code");
				var state = GetQuerystringValueOrNull(query, "state");
				
				properties = Options.StateDataFormat.Unprotect(state);
				if (properties == null)
				{
					return null;
				}

				// OAuth2 10.12 CSRF
				if (!ValidateCorrelationId(properties, this.Logger))
				{
					return new AuthenticationTicket(null, properties);
				}

				var requestPrefix = Request.Scheme + "://" + Request.Host;
				var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

				// Build up the body for the token request
				var body = new List<KeyValuePair<string, string>>();
				body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
				body.Add(new KeyValuePair<string, string>("code", code));
				body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
				body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
				body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));

				// Request the token
				var tokenResponse = await this.HttpClient.PostAsync(Options.ApiSettings.TokenEndpoint, new FormUrlEncodedContent(body));
				tokenResponse.EnsureSuccessStatusCode();
				var text = await tokenResponse.Content.ReadAsStringAsync();

				// Deserializes the token response
				var response = JObject.Parse(text);
				var accessToken = response.Value<string>("access_token");
				var expires = response.Value<string>("expires_in");
				var refreshToken = response.Value<string>("refresh_token");

				if (string.IsNullOrWhiteSpace(accessToken))
				{
					this.Logger.WriteWarning("Access token was not found");
					return new AuthenticationTicket(null, properties);
				}

				// Get the Google user
				var request = new HttpRequestMessage(HttpMethod.Get, Options.ApiSettings.GraphApiEndpoint);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				var graphResponse = await this.HttpClient.SendAsync(request, Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				text = await graphResponse.Content.ReadAsStringAsync();
				var user = JObject.Parse(text);

				var context = new GoogleAuthenticatedContext(Context, user, accessToken, refreshToken, expires)
				{
					Identity = new ClaimsIdentity(
						Options.AuthenticationType,
						ClaimsIdentity.DefaultNameClaimType,
						ClaimsIdentity.DefaultRoleClaimType)
				};

				if (!string.IsNullOrEmpty(context.Id))
					context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String, Options.AuthenticationType));

				if (!string.IsNullOrEmpty(context.GivenName))
					context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.GivenName, ClaimValueTypes.String, Options.AuthenticationType));
				
				if (!string.IsNullOrEmpty(context.FamilyName))
					context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.FamilyName, ClaimValueTypes.String, Options.AuthenticationType));
				
				if (!string.IsNullOrEmpty(context.Name))
					context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.Name, ClaimValueTypes.String, Options.AuthenticationType));

				if (!string.IsNullOrEmpty(context.Email))
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, ClaimValueTypes.String, Options.AuthenticationType));

				if (!string.IsNullOrEmpty(context.Profile))
					context.Identity.AddClaim(new Claim("urn:google:profile", context.Profile, ClaimValueTypes.String, Options.AuthenticationType));
				
				context.Properties = properties;

				await Options.Provider.Authenticated(context);

				return new AuthenticationTicket(context.Identity, context.Properties);
			}
			catch (Exception ex)
			{
				this.Logger.WriteError("Authentication failed", ex);
				return new AuthenticationTicket(null, properties);
			}
		}

	}
}