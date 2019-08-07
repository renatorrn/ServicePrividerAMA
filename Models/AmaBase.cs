using Adxstudio.Xrm.AspNet.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Identity;
using ServicePrividerAMA.SAML;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;
using System.Xml;
using System.Xml.Serialization;

namespace ServicePrividerAMA.Models
{
    public class AmaBase
    {

        private static readonly XmlSerializerNamespaces xmlNamespaces = new XmlSerializerNamespaces();

        public string ama_LocalName = ConfigurationManager.AppSettings["AMA_LocalName"];
        public string ama_UrlAttributes = ConfigurationManager.AppSettings["AMA_UrlAttribute"];
        public string ama_Destination = ConfigurationManager.AppSettings["AMA_Destination"];
        public string ama_AssertionConsumerServiceURL = ConfigurationManager.AppSettings["AMA_AssertionConsumerServiceURL"];
        public string ama_ProviderName = ConfigurationManager.AppSettings["AMA_ProviderName"];

        public string RequestSamlCreate()
        {
            XmlDocument doc = null;

            // Converter objeto para XmlDocument via stream usando serialização com os tipos AuthnRequestType e XmlDocument
            // http://support.microsoft.com/kb/815813/en-us
            try
            {

                var _request = AuthnRequestTypeCreate();

                MemoryStream stream = new MemoryStream();
                XmlSerializer requestSerializer = new XmlSerializer(_request.GetType());
                requestSerializer.Serialize(stream, _request, xmlNamespaces);
                stream.Flush();

                StreamReader reader = new StreamReader(stream);
                stream.Seek(0, SeekOrigin.Begin);
                XmlTextReader xmlReader = new XmlTextReader(new StringReader(reader.ReadToEnd()));

                XmlSerializer xmlDocumentSerializer = new XmlSerializer(typeof(XmlDocument));
                doc = (XmlDocument)xmlDocumentSerializer.Deserialize(xmlReader);
                doc.PreserveWhitespace = true;
            }
            catch (Exception ex)
            {
                throw new Exception("Erro ao converter objecto para XmlDocument: " + ex.ToString());
            }

            // assinatura:

            // Obter certificado de ficheiro
            X509Certificate2 cert = new X509Certificate2(HostingEnvironment.MapPath("~/SAML/Certificate/") + "capgemini.pfx", "");
            RSACryptoServiceProvider rsaCsp = (RSACryptoServiceProvider)cert.PrivateKey;
            UTF8Encoding ByteConverter = new UTF8Encoding();
            byte[] unsignedBytes = ByteConverter.GetBytes("");
            byte[] signature;



            // Código adaptado do exemplo em http://msdn.microsoft.com/en-us/library/k0zd758e.aspx
            try
            {
                XmlElement element = doc.DocumentElement;
                SignedXml signedXml = new SignedXml(element);

                using (RSA rsaa = cert.GetRSAPrivateKey())
                {
                    signature = rsaa.SignData(unsignedBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                }
                signedXml.SigningKey = cert.GetRSAPrivateKey();

                Reference reference = new Reference("#" + element.Attributes["ID"].Value);

                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigExcC14NTransform());

                signedXml.AddReference(reference);
                signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.ComputeSignature();
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                               
                XmlNode refNode = doc.GetElementsByTagName("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion").Item(0);
                element.InsertAfter(xmlDigitalSignature, refNode);
            }
            catch (Exception ex)
            {
                throw new Exception("Excepção ao assinar Xml:" + ex.ToString());
            }

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));

        }

        public void processLogoutResponse(XmlDocument xml, HttpContext context, XmlReader reader)
        {
            // desserializar xml para LogoutRequestType
            XmlSerializer serializer = new XmlSerializer(typeof(LogoutResponseType));
            LogoutResponseType response = (LogoutResponseType)serializer.Deserialize(reader);

            // verificar validade temporal:
            int validTimeFrame = 5;
            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeFrame)
            {
                throw new Exception("SAML Response fora do intervalo de validade - validade da resposta: " + response.IssueInstant);
            }

            // TODO: efectar restantes verificações da origem, do ID a que se refere a resposta, etc

            if ("urn:oasis:names:tc:SAML:2.0:status:Success".CompareTo(response.Status.StatusCode.Value) != 0)
            {
                // TODO: redireccionar para página de login...
                throw new Exception("Autenticação sem sucesso: " + response.Status.StatusCode.Value + " - " + response.Status.StatusMessage);
            }

            context.Response.Redirect("~/Default.aspx");

            context.Response.End();
        }

        public void processResponse(XmlDocument xml, HttpContext context, XmlReader reader, string relayState)
        {
            string nic = string.Empty, nomeCompleto = string.Empty;
            // desserializar xml para ResponseType
            XmlSerializer serializer = new XmlSerializer(typeof(ResponseType));
            ResponseType response = (ResponseType)serializer.Deserialize(reader);

            // verificar validade temporal:
            int validTimeFrame = 5;
            if (Math.Abs(response.IssueInstant.Subtract(DateTime.UtcNow).TotalMinutes) > validTimeFrame)
            {
                throw new Exception("SAML Response fora do intervalo de validade - validade da resposta: " + response.IssueInstant);
            }

            relayState = System.Text.UTF8Encoding.UTF8.GetString(System.Convert.FromBase64String(relayState));

            if ("urn:oasis:names:tc:SAML:2.0:status:Success".Equals(response.Status.StatusCode.Value))
            {
                AssertionType assertion = new AssertionType();
                for (int i = 0; i < response.Items.Length; i++)
                {
                    if (response.Items[i].GetType() == typeof(AssertionType))
                    {
                        assertion = (AssertionType)response.Items[i];
                        break;
                    }
                }

                // validade da asserção:
                DateTime now = DateTime.UtcNow;
                TimeSpan tSpan = new TimeSpan(0, 0, 150); // 2,5 minutos
                if (now < assertion.Conditions.NotBefore.Subtract(tSpan) ||
                    now >= assertion.Conditions.NotOnOrAfter.Add(tSpan))
                {
                    // Asserção inválida 
                    // TODO: redireccionar para página de erro/login
                    throw new Exception("Asserções temporalmente inválidas.");
                }

                AttributeStatementType attrStatement = new AttributeStatementType();
                for (int i = 0; i < assertion.Items.Length; i++)
                {
                    if (assertion.Items[i].GetType() == typeof(AttributeStatementType))
                    {
                        attrStatement = (AttributeStatementType)assertion.Items[i];
                        break;
                    }
                }

                foreach (object obj in attrStatement.Items)
                {
                    AttributeType attr = (AttributeType)obj;

                    if (attr.AnyAttr != null)
                    {
                        for (int i = 0; i < attr.AnyAttr.Length; i++)
                        {
                            XmlAttribute xa = attr.AnyAttr[i];
                            if (xa.LocalName.Equals("AttributeStatus") && xa.Value.Equals("Available"))
                            {
                                if (attr.AttributeValue != null && attr.AttributeValue.Length > 0)
                                    if (((string)attr.Name).Equals("http://interop.gov.pt/MDC/Cidadao/NIC"))
                                        nic = (string)attr.AttributeValue[0];
                                //else if (((string)attr.Name).Equals("http://interop.gov.pt/MDC/Cidadao/NomeCompleto"))
                                //    nomeCompleto = (string)attr.AttributeValue[0];
                            }
                        }
                    }
                }

                MembershipUser _user = Membership.GetUser(nic);
                // Verificar se utilizador existe
                if (_user != null)
                {
                    // Se existe, registar login... 
                    FormsAuthentication.SetAuthCookie(nic, false /* createPersistentCookie */);

                    // ...e redireccionar para página recebida no relayState
                    if (!string.IsNullOrEmpty(relayState))
                    {
                        relayState = relayState.Substring(relayState.IndexOf("=") + 1);
                        context.Response.Redirect(VirtualPathUtility.ToAbsolute(relayState));
                    }
                    else
                    {
                        context.Response.Redirect(VirtualPathUtility.ToAbsolute("~/Default.aspx")); // Ocorreu erro?
                    }
                }
                else
                {                  

                    // Se não existe, enviar o utilizador para a página de registo
                    // passar informação para a página que utilizará os dados obtidos:
                    context.Session.Add("Nic", nic);
                    context.Session.Add("RelayState", relayState);

                    context.Response.Redirect("~/Account/Register.aspx");

                    context.Response.End();
                }
            }
            else
            {
                //Caso o retorno não seja sucesso, definir qual dever ser 
                context.Response.Redirect("~/Account/Login.aspx");
                context.Response.End();
            }
        }



        private AuthnRequestType AuthnRequestTypeCreate()
        {
            AuthnRequestType _request = new AuthnRequestType();

            _request.ID = "_" + Guid.NewGuid().ToString();
            _request.Version = "2.0";
            _request.IssueInstant = DateTime.UtcNow;
            _request.Destination = ama_Destination;
            _request.Consent = "urn:oasis:names:tc:SAML:2.0:consent:unspecified";
            _request.ProtocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            _request.AssertionConsumerServiceURL = ama_AssertionConsumerServiceURL;
            _request.ProviderName = ama_ProviderName;
            _request.Issuer = new NameIDType();
            _request.Issuer.Value = "http://localhost:64181";
            _request.Extensions = new ExtensionsType();

            _request.Extensions.Any = new XmlElement[] { RequestAttributeCreate() };
            return _request;

        }

        private XmlElement RequestAttributeCreate()
        {

            XmlDocument docAux = new XmlDocument();
            docAux.PreserveWhitespace = true;
            RequestAttributesAMA rqAma = new RequestAttributesAMA();

            // Elemento RequestedAttributes
            XmlElement requestedAttributes = docAux.CreateElement("fa", ama_LocalName, ama_UrlAttributes);

            requestedAttributes.AppendChild(buildRequestedAttribute(docAux, rqAma.NIF, true));


            return requestedAttributes;
        }

        private XmlElement buildRequestedAttribute(XmlDocument xmlDoc, string attributeName, bool isRequired)
        {
            XmlElement requestedAttr = xmlDoc.CreateElement("fa", ama_LocalName, ama_UrlAttributes);
            requestedAttr.SetAttribute("Name", attributeName);
            requestedAttr.SetAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            requestedAttr.SetAttribute("isRequired", isRequired.ToString());

            return requestedAttr;
        }
    }
}