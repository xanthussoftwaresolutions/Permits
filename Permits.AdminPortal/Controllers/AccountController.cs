﻿using Permits.DataAccess.Managers;
using System.Web.Mvc;
using System.Web.Security;
using Permits.DataAccess;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Permits.AdminPortal.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Register()
        {
            string loginName = User.Identity.Name;
            UserManager UM = new UserManager();
            PermitEntitiesDb db = new PermitEntitiesDb();
            UserSignUpView UDV = UM.GetUserDataView(loginName);
            ViewBag.Role = new SelectList(db.UserRoles);
            return View(UDV);
        }

   
        [HttpPost]
        public ActionResult Register(UserSignUpView USV)
        {
            if (ModelState.IsValid)
            {
                UserManager UM = new UserManager();
                if (!UM.IsLoginNameExist(USV.LoginName))
                {
                    UM.AddUserAccount(USV);
                    FormsAuthentication.SetAuthCookie(USV.FirstName, false);
                    return RedirectToAction("Welcome", "Home");

                }
                else
                    ModelState.AddModelError("", "Login Name already taken.");
            }
            return View();
        }

        public ActionResult SignUp()
        {
            return View();
        }

   
        [HttpPost]
        public ActionResult SignUp(UserSignUpView USV)
        {
           
            if (ModelState.IsValid)
            {
                UserManager UM = new UserManager();
                if (!UM.IsLoginNameExist(USV.LoginName))
                {
                    UM.AddUserAccount(USV);
                    FormsAuthentication.SetAuthCookie(USV.FirstName, false);
                    return RedirectToAction("Welcome", "Home");

                }
                else
                    ModelState.AddModelError("", "Login Name already taken.");
            }
            return View();
        }

        [Authorize]
        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }


        public ActionResult LogIn()
        {
            return View();
        }

        [HttpPost]
        public ActionResult LogIn(UserLoginView ULV, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                UserManager UM = new UserManager();
                string password = UM.GetUserPassword(ULV.LoginName);

                if (string.IsNullOrEmpty(password))
                    ModelState.AddModelError("", "The user login or password provided is incorrect.");
                else
                {
                    if (ULV.Password.Equals(password))
                    {
                        //FormsAuthentication.SetAuthCookie(ULV.LoginName, false);
                        //return RedirectToAction("Welcome", "Home");
                        FormsAuthentication.RedirectFromLoginPage(ULV.LoginName, false);
                    }
                    else
                    {
                        ModelState.AddModelError("", "The password provided is incorrect.");
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(ULV);
        }
    }
}