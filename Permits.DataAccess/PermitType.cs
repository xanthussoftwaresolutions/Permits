//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Permits.DataAccess
{
    using System;
    using System.Collections.Generic;
    
    public partial class PermitType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PermitType()
        {
            this.PermitSubType = new HashSet<PermitSubType>();
        }
    
        public int PermitTypeID { get; set; }
        public string PermitTypeDescription { get; set; }
        public int AgencyID { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<PermitSubType> PermitSubType { get; set; }
    }
}
