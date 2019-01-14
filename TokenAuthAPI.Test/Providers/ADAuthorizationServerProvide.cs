using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

using TokenAuthAPI.Test;
using Microsoft.Owin.Security;
using TokenAuthAPI;
using System;

using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth.Manager.Server;
using System.Collections.Generic;
using System.Web.Mvc;
using System.Runtime.Remoting.Contexts;

using System.Data;
using System.Data.Entity;
using TokenAuthAPI.Test.Models;
using System.Linq;


//using ActiveDirectoryTool.Models;
//using AccountManagement.Client.BackEnd.Models;
//using AccountManagement.Client.BackEnd.Models;

namespace TokenAuthAPI.Providers

{


    public class ADAuthorizationServerProvider : OAuthAuthorizationServerProvider

    {
      

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "capgefi.local"))
            {
                // validate the credentials
                bool isValid = pc.ValidateCredentials(context.UserName, context.Password);
               
                if (!isValid)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }


            //var identity = new ClaimsIdentity(context.Options.AuthenticationType);


            //ContextType authenticationType = ContextType.Domain;
            PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, "capgefi.local");
            UserPrincipal userPrincipal = null;
            userPrincipal = UserPrincipal.FindByIdentity(principalContext, context.UserName);

           var roles = Callrole(context.UserName);
           //var app = string.Format("{0} {1}", CallAppUser(context.UserName), CallAppUserurl(context.UserName));
           var url= CallAppUserurl(context.UserName);
            //UserPrincipal userPrincipal = null;
            //userPrincipal = UserPrincipal.FindByIdentity(context, User.Identity.Name);
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("user", context.UserName));
            //identity.AddClaim(new Claim("role", roles));
            //identity.AddClaim(new Claim("app", app));
            //identity.AddClaim(new Claim("url", url));
            //identity.AddClaim(new Claim("role", roles));
            //identity.AddClaim(new Claim("role", "user"));
            //identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
            //var identity = new ClaimsIdentity(context.Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            //identity.AddClaim(new Claim(ClaimTypes.Role, ));
            //  smacEntities2 db = new smacEntities2();
            //  //var apps = db.UserApps.Include(a => a.AppWeb1.Nombre).Include(a => a.AppWeb1.Enlace);
            //  //apps= apps.Where(a => a.Users.Usuario.Contains(context.UserName));
            //var APP = db.UserApps.Include(a => a.AppWeb1.UserApps.).Include(a => a.AppWeb1.Enlace);
            //  APP = APP.Where(a => a.Users.Usuario.Contains(context.UserName));
            //  //var apps = APP.UserApps.Contains(context.UserName); 
            //  foreach (var tapp in APP)
            //  {
            //      identity.AddClaim(new Claim("apps", tapp.AppWeb1.Nombre));
            //  }

            //var groups = userPrincipal.GetAuthorizationGroups();
            //foreach (var @group in groups) 
            //{
            //    identity.AddClaim(new Claim("roles", @group.Name));
            //}
            //ROLES
            smacEntities2 db = new smacEntities2();
            var role = from a in db.Users
                       select a;
            role = role.Where(a => a.Usuario.Contains(context.UserName));
            if (role == null)
                {
                RegistrarUsuario(context.UserName);
                role = role.Where(a => a.Usuario.Contains(context.UserName));
            }
            foreach (var @roless in role)
            {
                identity.AddClaim(new Claim("role", @roless.Role1.Role1));
            }

            //APP
            var app = from a in db.UserApps
                      select a;
            app= app.Where(a => a.Users.Usuario.Contains(context.UserName));
            foreach (var @roless in app)
            {
                identity.AddClaim(new Claim(@roless.AppWeb1.Nombre, @roless.AppWeb1.Enlace));
                //identity.AddClaim(new Claim("url", @roless.AppWeb1.Enlace));
            }


            var user = userPrincipal;
            //UserPrincipal user = null;
            //Create a PrincipleContext that will search the full domain
            //ie not just the site's user OU
            //FQDC = Fully Qualified Domain Controller
            string userName = userPrincipal.Name;
            //using (var context2 = new PrincipalContext(ContextType.Domain, "capgefi.local"))
            //{

            //    {
            //        if ((userPrincipal = UserPrincipal.FindByIdentity(principalContext, context.UserName)) != null)
            //        {
            //            // Search for current groups
            //            PrincipalSearchResult<Principal> groups2 = userPrincipal.GetGroups();

            //            // Iterate group membership
            //            foreach (GroupPrincipal g in groups2)
            //            {
            //                //UserData.roles = string.Format("{0} {1}", "Role:" + g.Name, "Nombre:" + user.DisplayName);
            //                UserData.user = string.Format("{0}", user.UserPrincipalName);
            //                UserData.roles = string.Format("{0}", "Role:" + g.Name);
            //            }
            //        }
            //    }
            //}
           



            context.Validated(identity);
        }


        static string Callrole(string usuario)
            
        {

            smacEntities2 db = new smacEntities2();

            string roles;
            //var role= db.Users.FirstOrDefault(e => e.Usuario.Contains(usuario));
            var role = from a in db.Users
                       select a;
            role = role.Where(a => a.Usuario.Contains(usuario));
            if (role != null)
            {
                var x = role.OrderBy(a => a.Role1.Role1).ToString();
                return roles = x.ToString();
                //return roles = role.Role1.Role1;
                //UserData.roles = roles;
            }
            else
            {
                RegistrarUsuario(usuario);
           
                var roless = db.Users.FirstOrDefault(e => e.Usuario.Contains(usuario));
        
                    return roles = roless.Role1.Role1;
            }


            return null;
        }

        static string CallAppUser(string usuario)

        {

            smacEntities2 db = new smacEntities2();

            string apps;
            var app = db.UserApps.FirstOrDefault(e => e.Users.Usuario.Contains(usuario));
            if (app != null)
            {

                return apps = app.AppWeb1.Nombre;
                //UserData.roles = roles;
            }
            //else
            //{
            //    RegistrarUsuario(usuario);

            //    var roless = db.Users.FirstOrDefault(e => e.Usuario.Contains(usuario));

            //    return app = roless.Role1.Role1;
            //}


            return null;
        }

        static string CallAppUserurl(string usuario)

        {

            smacEntities2 db = new smacEntities2();

            string apps;
            var app = db.UserApps.FirstOrDefault(e => e.Users.Usuario.Contains(usuario));
            if (app != null)
            {

                return apps = app.AppWeb1.Enlace;
                //UserData.roles = roles;
            }
            //
            //{
            //    RegistrarUsuario(usuario);

            //    var roless = db.Users.FirstOrDefault(e => e.Usuario.Contains(usuario));

            //    return app = roless.Role1.Role1;
            //}


            return null;
        }


        static string RegistrarUsuario(string usuario)

        {

            smacEntities2 db = new smacEntities2();
            Users ord = new Users
            {
                Usuario = usuario,
                Role= 3
                            // …
            };

            // Add the new object to the Orders collection.
            db.Users.Add(ord);

            // Submit the change to the database.
           
                db.SaveChanges();
           


            return null;
        }
        //internal struct UserGroups
        //{
        //    internal IEnumerable<GroupPrincipal> Groups { get; set; }
        //    internal UserPrincipal User { get; set; }
        //}
        //identity.AddClaim(new Claim("sub", context.UserName));
        //public ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        //{
        //    var identity = new ClaimsIdentity("", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

        //    var groups = userPrincipal.GetAuthorizationGroups();
        //    foreach (var @group in groups)
        //    {
        //        identity.AddClaim(new Claim(ClaimTypes.Role, @group.Name));
        //    }
        //    // add your own claims if you need to add more information stored on the cookie

        //    return identity;
        //}
    }
}
