using System;
using System.Collections.Specialized;
using System.Net;

namespace SMT
{

    public class DcHook : IDisposable
    {
        private readonly WebClient dWebClient;
        private static readonly NameValueCollection discordValues = new NameValueCollection();
        public string WebHook { get; set; }
        public string UserName { get; set; }
        public string ProfilePicture { get; set; }

        public DcHook()
        {
            dWebClient = new WebClient();

        }


        public void SendMessage(string msgSend)
        {
            discordValues.Add("username", UserName);
            discordValues.Add("avatar_url", ProfilePicture);
            discordValues.Add("content", msgSend);

            dWebClient.UploadValues(WebHook, discordValues);
        }

        public void Dispose()
        {
            dWebClient.Dispose();
        }
    }
}
