using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ServicePrividerAMA.SAML
{
    public class RequestAttributesAMA
    {

        public string DataNascimento = "http://interop.gov.pt/MDC/Cidadao/DataNascimento";
        public string Nacionalidade = "http://interop.gov.pt/MDC/Cidadao/Nacionalidade";
        public string NIC = "http://interop.gov.pt/MDC/Cidadao/NIC";
        public string NIF = "http://interop.gov.pt/MDC/Cidadao/NIF";
        public string NIFCifrado = "http://interop.gov.pt/MDC/Cidadao/NIFCifrado";
        public string NISS = "http://interop.gov.pt/MDC/Cidadao/NISS";
        public string NISSCifrado = "http://interop.gov.pt/MDC/Cidadao/NISSCifrado";
        public string NomeApelido = "http://interop.gov.pt/MDC/Cidadao/NomeApelido";
        public string NomeCompleto = "http://interop.gov.pt/MDC/Cidadao/NomeCompleto";
        public string NomeProprio = "http://interop.gov.pt/MDC/Cidadao/NomeProprio";
        public string NumeroSerie = "http://interop.gov.pt/MDC/Cidadao/NumeroSerie";
        public string PassarConsentimento = "http://interop.gov.pt/MDC/FA/PassarConsentimento";       
    }
}