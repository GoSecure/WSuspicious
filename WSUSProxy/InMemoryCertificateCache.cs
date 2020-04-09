using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Titanium.Web.Proxy.Network;

namespace WSUSProxy
{
    public sealed class InMemoryCertificateCache : ICertificateCache
    {
        private Dictionary<string, X509Certificate2> dictRootCerts = new Dictionary<string, X509Certificate2>();
        private Dictionary<string, X509Certificate2> dictCerts = new Dictionary<string, X509Certificate2>();

        public void SaveRootCertificate(string pathOrName, string password, X509Certificate2 certificate)
        {
            dictRootCerts.Add(pathOrName, certificate);
        }

        public void SaveCertificate(string subjectName, X509Certificate2 certificate)
        {
            dictCerts.Add(subjectName, certificate);
        }

        X509Certificate2 ICertificateCache.LoadRootCertificate(string pathOrName, string password, X509KeyStorageFlags storageFlags)
        {
            if (dictRootCerts.ContainsKey(pathOrName))
            {
                return dictRootCerts[pathOrName];
            }
            else
            {
                return null;
            }
        }

        X509Certificate2 ICertificateCache.LoadCertificate(string subjectName, X509KeyStorageFlags storageFlags)
        {
            if (dictCerts.ContainsKey(subjectName))
            {
                return dictCerts[subjectName];
            }
            else
            {
                return null;
            }
        }

        public void Clear()
        {
            dictRootCerts = new Dictionary<string, X509Certificate2>();
            dictCerts = new Dictionary<string, X509Certificate2>();
        }
    }
}
