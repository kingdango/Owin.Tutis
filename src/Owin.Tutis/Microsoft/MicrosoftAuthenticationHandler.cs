using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis.Microsoft
{
	public class MicrosoftAuthenticationHandler : OAuth2AuthenticationHandler<MicrosoftAuthenticationOptions>
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

				var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

				var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

				var response = await this.HttpClient.PostAsync(Options.ApiSettings.TokenEndpoint, requestContent, Request.CallCancelled);
				response.EnsureSuccessStatusCode();
				var oauthTokenResponse = await response.Content.ReadAsStringAsync();

				var oauth2Token = JObject.Parse(oauthTokenResponse);
				var accessToken = oauth2Token["access_token"].Value<string>();

				// Refresh token is only available when wl.offline_access is request.
				// Otherwise, it is null.
				var refreshToken = oauth2Token.Value<string>("refresh_token");
				var expire = oauth2Token.Value<string>("expires_in");

				if (string.IsNullOrWhiteSpace(accessToken))
				{
					this.Logger.WriteWarning("Access token was not found");
					return new AuthenticationTicket(null, properties);
				}

				var graphResponse = await this.HttpClient.GetAsync(
					Options.ApiSettings.GraphApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				var accountString = await graphResponse.Content.ReadAsStringAsync();
				var accountInformation = JObject.Parse(accountString);

				var context = new MicrosoftAccountAuthenticatedContext(Context, accountInformation, accessToken,
					refreshToken, expire);
				context.Identity = new ClaimsIdentity(
					new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, context.Id, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.Name, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("urn:microsoftaccount:id", context.Id, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                        new Claim("urn:microsoftaccount:name", context.Name, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType)
                    },
					Options.AuthenticationType,
					ClaimsIdentity.DefaultNameClaimType,
					ClaimsIdentity.DefaultRoleClaimType);
				if (!string.IsNullOrWhiteSpace(context.Email))
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
				}

				await Options.Provider.Authenticated(context);

				context.Properties = properties;

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