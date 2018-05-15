using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.ComponentModel.DataAnnotations;

namespace PhoenixRising.Website.Models
{
    public class Register
    {
        //TODO: What are the requirements for these
        [Required]
        [MaxLength(100)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public string Email { get; set; }

        [Required]
        [MaxLength(100)]
        [Display(Name = "Username")]
        public string Nicknane { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Password")]
        public string password1 { get; set; }

        [Required]
        [MinLength(4)]
        [Display(Name = "Re-Type Password")]
        [System.ComponentModel.DataAnnotations.Compare("password1")]
        public string password2 { get; set; }
    }
}