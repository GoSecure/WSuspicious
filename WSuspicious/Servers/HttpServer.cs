using System;
using System.Net;
using System.Text;

namespace WSuspicious.Servers
{
    class HttpServer
    {
        public HttpListener listener;
        public byte[] fileData;

        public HttpServer(int port, byte[] payload)
        {
            listener = new HttpListener();
            listener.Prefixes.Add(String.Format("http://127.0.0.1:{0}/", port));

            Console.WriteLine(String.Format("Starting Payload delivery server on http://127.0.0.1:{0}/", port));

            fileData = payload;
        }

        public async void Start()
        {
            bool runServer = true;
            listener.Start();

            // While a user hasn't visited the `shutdown` url, keep on handling requests
            while (runServer)
            {
                // Will wait here until we hear from a connection
                HttpListenerContext ctx = await listener.GetContextAsync();

                // Peel out the requests and response objects
                HttpListenerRequest req = ctx.Request;
                HttpListenerResponse resp = ctx.Response;

                resp.ContentType = "application/octet-stream";
                resp.ContentEncoding = Encoding.UTF8;
                resp.ContentLength64 = fileData.Length;

                // Write out to the response stream (asynchronously), then close it
                await resp.OutputStream.WriteAsync(fileData, 0, fileData.Length);
                resp.Close();
            }
        }

        public void Stop ()
        {
            listener.Close();
        }
    }
}
