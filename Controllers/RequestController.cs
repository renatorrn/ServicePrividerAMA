using ServicePrividerAMA.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ServicePrividerAMA.Controllers
{

   

    public class RequestController : Controller
    {

        public string MontaRequestXML()
        {

            AmaBase amaBase = new AmaBase();

            var SAMLRequest = amaBase.RequestSamlCreate();

            return SAMLRequest;
        }

        


    }
}