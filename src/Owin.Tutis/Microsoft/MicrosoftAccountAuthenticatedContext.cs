using System;
using System.Globalization;
using Microsoft.Owin;
using Newtonsoft.Json.Linq;

namespace Kingdango.Owin.Tutis.Microsoft
{
	public class MicrosoftAccountAuthenticatedContext : OAuth2AuthenticatedContext
	{
		public MicrosoftAccountAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expires)
			: base(context)
		{
			this.User = User;
			this.AccessToken = accessToken;
			int result;
			if (int.TryParse(expires, NumberStyles.Integer, (IFormatProvider)CultureInfo.InvariantCulture, out result))
				this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)result));
			this.Id = TryGetValue(user, "id");
			this.Name = TryGetValue(user, "name");
			this.Link = TryGetValue(user, "link");
			this.Email = TryGetValue(user, "email");
		}
	}
}