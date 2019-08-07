using ServicePrividerAMA.Controllers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace ServicePrividerAMA
{
    public partial class SendRequest : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {


            if (!IsPostBack)
            {

                RequestController requestController = new RequestController();

                //this.RelayState.Value = relayStateToBepersistedAcross;

                this.SAMLRequest.Value = requestController.MontaRequestXML();

                //this.form1.Action = appSettings.Get("formActionAuthnDestination");
                this.form1.Action = ConfigurationManager.AppSettings["AMA_formActionAuthnDestination"];

            }

        }
    }
}