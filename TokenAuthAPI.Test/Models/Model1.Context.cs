﻿//------------------------------------------------------------------------------
// <auto-generated>
//     Este código se generó a partir de una plantilla.
//
//     Los cambios manuales en este archivo pueden causar un comportamiento inesperado de la aplicación.
//     Los cambios manuales en este archivo se sobrescribirán si se regenera el código.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TokenAuthAPI.Test.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class smacEntities2 : DbContext
    {
        public smacEntities2()
            : base("name=smacEntities2")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<Actividades> Actividades { get; set; }
        public virtual DbSet<ActividadEstatus> ActividadEstatus { get; set; }
        public virtual DbSet<AppLogins> AppLogins { get; set; }
        public virtual DbSet<AppWeb> AppWeb { get; set; }
        public virtual DbSet<Cargo> Cargo { get; set; }
        public virtual DbSet<Empleados> Empleados { get; set; }
        public virtual DbSet<Estatus> Estatus { get; set; }
        public virtual DbSet<EstructuraOrganizacional> EstructuraOrganizacional { get; set; }
        public virtual DbSet<GrupoOcupacional> GrupoOcupacional { get; set; }
        public virtual DbSet<Periodo> Periodo { get; set; }
        public virtual DbSet<Politicas> Politicas { get; set; }
        public virtual DbSet<Role> Role { get; set; }
        public virtual DbSet<sysdiagrams> sysdiagrams { get; set; }
        public virtual DbSet<UnidadOrganizativa> UnidadOrganizativa { get; set; }
        public virtual DbSet<UnidadOrganizativaPoliticas> UnidadOrganizativaPoliticas { get; set; }
        public virtual DbSet<UserApps> UserApps { get; set; }
        public virtual DbSet<Users> Users { get; set; }
    }
}