using System;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis
{
	public abstract class OAuth2AuthenticatedContext : BaseContext
	{
		protected OAuth2AuthenticatedContext(IOwinContext context) : base(context)
		{
		}

		public JObject User { get; protected set; }

		public string AccessToken { get; protected set; }

		public TimeSpan? ExpiresIn { get; set; }

		public string Id { get; protected set; }

		public string Name { get; protected set; }

		public string Link { get; protected set; }

		public string Email { get; protected set; }

		public ClaimsIdentity Identity { get; set; }

		public AuthenticationProperties Properties { get; set; }

		#region Private Helpers
		
		protected static string TryGetValue(JObject user, string propertyName)
		{
			JToken value;
			return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
		}

		// Get the given subProperty from a property.
		protected static string TryGetValue(JObject user, string propertyName, string subProperty)
		{
			JToken value;
			if (user.TryGetValue(propertyName, out value))
			{
				var subObject = JObject.Parse(value.ToString());
				if (subObject != null && subObject.TryGetValue(subProperty, out value))
				{
					return value.ToString();
				}
			}
			return null;
		}

		// Get the given subProperty from a list property.
		protected static string TryGetFirstValue(JObject user, string propertyName, string subProperty)
		{
			JToken value;
			if (user.TryGetValue(propertyName, out value))
			{
				var array = JArray.Parse(value.ToString());
				if (array != null && array.Count > 0)
				{
					var subObject = JObject.Parse(array.First.ToString());
					if (subObject != null)
					{
						if (subObject.TryGetValue(subProperty, out value))
						{
							return value.ToString();
						}
					}
				}
			}
			return null;
		}

		#endregion
	}
}