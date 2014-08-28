using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis.Facebook
{
	public class FacebookAuthenticationHandler : OAuth2AuthenticationHandler<FacebookAuthenticationOptions>
	{
		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;

			try
			{
				var query = Request.Query;

				LogIfQuerystringContainsError(query);

				var code = GetQuerystringValueOrNull(query, "code");
				if (code == null) // Null if the remote server returns an error.
					return new AuthenticationTicket(null, properties);

				var state = GetQuerystringValueOrNull(query, "state");
				
				properties = Options.StateDataFormat.Unprotect(state);
				if (properties == null) return null;

				// OAuth2 10.12 CSRF
				if (!ValidateCorrelationId(properties, this.Logger))
					return new AuthenticationTicket(null, properties);

				var requestPrefix = Request.Scheme + "://" + Request.Host;
				var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

				var tokenRequest = "grant_type=authorization_code" +
									  "&code=" + Uri.EscapeDataString(code) +
									  "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
									  "&client_id=" + Uri.EscapeDataString(Options.AppId) +
									  "&client_secret=" + Uri.EscapeDataString(Options.AppSecret);

				var tokenResponse = await this.HttpClient.GetAsync(Options.ApiSettings.TokenEndpoint + "?" + tokenRequest, Request.CallCancelled);
				tokenResponse.EnsureSuccessStatusCode();

				var text = await tokenResponse.Content.ReadAsStringAsync();
				var form = WebHelpers.ParseForm(text);

				var accessToken = form["access_token"];
				var expires = form["expires"];

				var graphResponse = await this.HttpClient.GetAsync(Options.ApiSettings.GraphApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				text = await graphResponse.Content.ReadAsStringAsync();
				var user = JObject.Parse(text);

				var context = new FacebookAuthenticatedContext(Context, user, accessToken, expires)
				{
					Identity = new ClaimsIdentity(
						Options.AuthenticationType,
						ClaimsIdentity.DefaultNameClaimType,
						ClaimsIdentity.DefaultRoleClaimType)
				};

				if (!string.IsNullOrEmpty(context.Id))
					context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));

				if (!string.IsNullOrEmpty(context.UserName))
					context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				
				if (!string.IsNullOrEmpty(context.Email))
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				
				if (!string.IsNullOrEmpty(context.Name))
				{
					context.Identity.AddClaim(new Claim("urn:facebook:name", context.Name, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));

					// Many Facebook accounts do not set the UserName field.  Fall back to the Name field instead.
					if (string.IsNullOrEmpty(context.UserName))
						context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				}

				if (!string.IsNullOrEmpty(context.Link))
					context.Identity.AddClaim(new Claim("urn:facebook:link", context.Link, Options.ApiSettings.XmlSchemaString, Options.AuthenticationType));
				
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