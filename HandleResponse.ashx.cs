using ServicePrividerAMA.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Schema;

namespace ServicePrividerAMA
{
    /// <summary>
    /// Summary description for HandleResponse
    /// </summary>
    public class HandleResponse : IHttpHandler
    {
        string nic = string.Empty, nomeCompleto = string.Empty;
        XmlReader reader;
        string relayState, requestData;

        public void ProcessRequest(HttpContext context)
        {
            AmaBase amaBase = new AmaBase();


            relayState = context.Request.Form["RelayState"];
            requestData = context.Request.Form["SAMLResponse"];

            // testar se pedido foi executado via HTTP POST:
            if (context.Request.HttpMethod != "POST")
            {
                // Pedido inválido
                // TODO: redireccionar para página de erro/login
                throw new Exception("Pedido inválido: não efectuado via HTTP POST");
            }
            if (string.IsNullOrEmpty(requestData))
            {
                throw new Exception("Recebido pedido de autenticapção inválido (SAMLResponse vazio)");
            }

            byte[] reqDataB64 = Convert.FromBase64String(requestData);
            string reqData = Encoding.UTF8.GetString(reqDataB64);
            XmlDocument xml = new XmlDocument();
            xml.PreserveWhitespace = true;

            try
            {
                xml.LoadXml(reqData);
            }
            catch (System.Xml.XmlException ex)
            {
                throw new Exception("Excepção ao carregar xml: " + ex.ToString());
            }

            reader = new XmlTextReader(new StringReader(xml.OuterXml));

            #region schema validation
            // exemplo de validação do xml obtido:
            string path = HttpContext.Current.Server.MapPath(".");
            path = path.Replace('\\', '/');
            if (!path.EndsWith("/"))
                path = path + "/../";
            XmlSchemaSet schemaSet = new XmlSchemaSet();
            schemaSet.Add("http://www.w3.org/2000/09/xmldsig#", path + "ServicePrividerAMA/SAML/Schemas/xmldsig-core-schema.xsd");
            schemaSet.Add("http://www.w3.org/2001/04/xmlenc#", path + "ServicePrividerAMA/SAML/Schemas/xenc-schema.xsd");
            schemaSet.Add("urn:oasis:names:tc:SAML:2.0:assertion", path + "ServicePrividerAMA/SAML/Schemas/saml-schema-assertion-2.0.xsd");
            schemaSet.Add("urn:oasis:names:tc:SAML:2.0:protocol", path + "ServicePrividerAMA/SAML/Schemas/saml-schema-protocol-2.0.xsd");
            schemaSet.Compile();
            xml.Schemas = schemaSet;
            // Sets the Xml validator event handler (if it's fired then the schema has error)
            ValidationEventHandler validator = delegate (object obj, ValidationEventArgs args)
            {
                throw new Exception("Erro na validação das schemas: " + args.Message);
            };
            // validates the document
            xml.Validate(validator);
            xml.Validate(validator);
            #endregion

            string certificateB64 = xml.GetElementsByTagName("X509Certificate", "http://www.w3.org/2000/09/xmldsig#").Item(0).InnerText;
            X509Certificate2 certificate = new X509Certificate2(Convert.FromBase64String(certificateB64));
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            // sets the timeout for retrieving the certificate validation
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
            if (!chain.Build(certificate))
            {
                throw new Exception("Assinatura tem certificado inválido");
            }
            if (!xml.PreserveWhitespace)
            {
                throw new Exception("SAMLRequest não preserva espaços em branco");
            }
            SignedXml signedXmlForValidation = new SignedXml(xml);
            XmlNodeList nodeList = xml.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            if (nodeList.Count == 0)
            {
                throw new Exception("SAMLRequest não está assinado.");
            }
            signedXmlForValidation.LoadXml((XmlElement)nodeList[0]);
            if (!signedXmlForValidation.CheckSignature())
            {
                throw new Exception("SAMLRequest tem assinatura inválida.");
            }

            // detectar tipo recebido:
            switch (xml.DocumentElement.LocalName.ToUpper())
            {
                case "RESPONSE": amaBase.processResponse(xml, context, reader, relayState); break;

                default:
                    // tipo de resposta desconhecido ou não processável...
                    throw new Exception("Formato de mensagem desconhecido: " + xml.DocumentElement.LocalName);
            }
        }

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }
    }
}