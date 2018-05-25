using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class UpdatePermissions
    {
        [Required]
        [MaxLength(100)]
        [Display(Name = "Username")]
        public string UserName { get; set; }

        public bool Administrator { get; set; }
        public bool Developer { get; set; }
        public bool Banned { get; set; }
        public bool CommunityManager { get; set; }
    }
}