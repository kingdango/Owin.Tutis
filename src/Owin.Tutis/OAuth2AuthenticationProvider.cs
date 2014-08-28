using System;
using System.Threading.Tasks;

namespace Kingdango.Owin.Tutis
{
	public class OAuth2AuthenticationProvider
	{
		public Func<OAuth2AuthenticatedContext, Task> OnAuthenticated { get; set; }

		public Func<OAuth2ReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

		public Action<OAuth2ApplyRedirectContext> OnApplyRedirect { get; set; }

		public OAuth2AuthenticationProvider()
		{
			this.OnAuthenticated = (Func<OAuth2AuthenticatedContext, Task>) (context => (Task) Task.FromResult<object>((object) null));
			this.OnReturnEndpoint = (Func<OAuth2ReturnEndpointContext, Task>) (context => (Task) Task.FromResult<object>((object) null));
			this.OnApplyRedirect = (Action<OAuth2ApplyRedirectContext>) (context => context.Response.Redirect(context.RedirectUri));
		}

		public Task Authenticated(OAuth2AuthenticatedContext context)
		{
			return this.OnAuthenticated(context);
		}

		public Task ReturnEndpoint(OAuth2ReturnEndpointContext context)
		{
			return this.OnReturnEndpoint(context);
		}

		public void ApplyRedirect(OAuth2ApplyRedirectContext context)
		{
			this.OnApplyRedirect(context);
		}
	}
}