//------------------------------------------------------------------------------
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
    using System.Collections.Generic;
    
    public partial class Estatus
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Estatus()
        {
            this.UnidadOrganizativaPoliticas = new HashSet<UnidadOrganizativaPoliticas>();
        }
    
        public int Id { get; set; }
        public string Estatus1 { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UnidadOrganizativaPoliticas> UnidadOrganizativaPoliticas { get; set; }
    }
}