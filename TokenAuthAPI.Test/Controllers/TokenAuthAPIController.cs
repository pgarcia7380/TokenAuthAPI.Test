using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using TokenAuthAPI.Providers;
using TokenAuthAPI.Test;

namespace TokenAuthAPI.Controllers
{
    public class APIController : ApiController
    {
        //[Authorize(Roles = @"IMASUBADMIN")]
        [Authorize]
        [Route("IsTokenAuthorized")]
        public IHttpActionResult Get()
        {
            ClaimsIdentity claimsIdentity = User.Identity as ClaimsIdentity;

            var claims = claimsIdentity.Claims.Select(x => new { type = x.Type, value = x.Value });

            return Ok(claims);
        }

       
    }
}