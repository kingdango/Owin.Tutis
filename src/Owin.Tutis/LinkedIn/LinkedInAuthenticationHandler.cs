using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis.LinkedIn
{
	public class LinkedInAuthenticationHandler : OAuth2AuthenticationHandler<LinkedInAuthenticationOptions>
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
				var tokenResponse =
					await this.HttpClient.PostAsync(Options.ApiSettings.TokenEndpoint, new FormUrlEncodedContent(body));
				tokenResponse.EnsureSuccessStatusCode();
				var text = await tokenResponse.Content.ReadAsStringAsync();

				// Deserializes the token response
				var response = JsonConvert.DeserializeObject<dynamic>(text);
				var accessToken = (string)response.access_token;
				var expires = (string)response.expires_in;

				// Get the LinkedIn user
				var userRequest = new HttpRequestMessage(HttpMethod.Get, Options.ApiSettings.GraphApiEndpoint + "?oauth2_access_token=" + Uri.EscapeDataString(accessToken));
				userRequest.Headers.Add("x-li-format", "json");
				var graphResponse = await this.HttpClient.SendAsync(userRequest, Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				text = await graphResponse.Content.ReadAsStringAsync();
				var user = JObject.Parse(text);

				var context = new LinkedInAuthenticatedContext(Context, user, accessToken, expires);
				context.Identity = new ClaimsIdentity(
					Options.AuthenticationType,
					ClaimsIdentity.DefaultNameClaimType,
					ClaimsIdentity.DefaultRoleClaimType);
				if (!string.IsNullOrEmpty(context.Id))
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.UserName))
				{
					context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.Email))
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.Name))
				{
					context.Identity.AddClaim(new Claim("urn:linkedin:name", context.Name, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.Link))
				{
					context.Identity.AddClaim(new Claim("urn:linkedin:url", context.Link, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.AccessToken))
				{
					context.Identity.AddClaim(new Claim("urn:linkedin:accesstoken", context.AccessToken, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}
				context.Properties = properties;

				await Options.Provider.Authenticated(context);

				return new AuthenticationTicket(context.Identity, context.Properties);
			}
			catch (Exception ex)
			{
				this.Logger.WriteError(ex.Message);
			}
			return new AuthenticationTicket(null, properties);
		}
	}
}