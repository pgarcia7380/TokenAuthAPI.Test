using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

using TokenAuthAPI.Test;
using Microsoft.Owin.Security;
using TokenAuthAPI;


using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth.Manager.Server;

using System.Threading;

namespace TokenAuthAPI.Test
{
    public static class CustomClaims
    {
        public const string role = "http://example/identity/claims/role";
      
    }

    
}