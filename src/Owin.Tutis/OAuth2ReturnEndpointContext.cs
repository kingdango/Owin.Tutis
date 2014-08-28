using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Kingdango.Owin.Tutis
{
	public class OAuth2ReturnEndpointContext : ReturnEndpointContext
	{
		public OAuth2ReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
		{
		}
	}
}