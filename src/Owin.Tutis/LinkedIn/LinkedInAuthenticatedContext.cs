using System;
using System.Globalization;
using Microsoft.Owin;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis.LinkedIn
{
	public class LinkedInAuthenticatedContext : OAuth2AuthenticatedContext
	{
		public string UserName { get; private set; }

		public LinkedInAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
			: base(context)
		{
			this.User = user;
			this.AccessToken = accessToken;
			int result;
			if (int.TryParse(expires, NumberStyles.Integer, (IFormatProvider)CultureInfo.InvariantCulture, out result))
				this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)result));
			this.Id = TryGetValue(user, "id");
			this.Name = TryGetValue(user, "name");
			this.Link = TryGetValue(user, "link");
			this.UserName = TryGetValue(user, "formattedName").Replace(" ", "");
			this.Email = TryGetValue(user, "email");
		}
	}
}