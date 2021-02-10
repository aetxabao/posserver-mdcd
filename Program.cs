using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Xml.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PosServer
{
    public class Message
    {
        public string From { get; set; }
        public string To { get; set; }
        public string Msg { get; set; }
        public string Stamp { get; set; }

        public override string ToString()
        {
            return $"From: {From}\nTo: {To}\n{Msg}\nStamp: {Stamp}";
        }
    }

    public class Server
    {
        public static int PORT = 14300;
        public static int TAM = 8192;

        public static Dictionary<string, List<Message>> repo = new Dictionary<string, List<Message>>();
        // Para guardar las claves públicas de los clientes
        public static Dictionary<string, string> crts = new Dictionary<string, string>();
        // Para el propio servidor
        public static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(3072);

        // Para verificar mensajes de los clientes
        public static bool Verify(Message m, string pubKey)
        {
            try
            {
                string txt = m.From + m.To + m.Msg;
                string sha = X.ShaHash(txt);
                return X.VerifyData(sha, m.Stamp, pubKey);
            }
            catch (Exception)
            {
                return false;
            }
        }
        // Para verificar mensajes de los clientes
        public static bool Verify(Message m)
        {
            string pubKey;
            if (crts.TryGetValue(m.From, out pubKey))
            {
                return Verify(m, pubKey);
            }
            else
            {
                return false;
            }
        }
        //Para firmar mensajes de respuesta del servidor
        public static void Sign(ref Message m, RSACryptoServiceProvider rsa)
        {
            string txt = m.From + m.To + m.Msg;
            string sha = X.ShaHash(txt);
            m.Stamp = X.SignedData(sha, rsa);
        }

        public static IPAddress GetLocalIpAddress()
        {
            List<IPAddress> ipAddressList = new List<IPAddress>();
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[0];
            int t = ipHostInfo.AddressList.Length;
            string ip;
            for (int i = 0; i < t; i++)
            {
                ip = ipHostInfo.AddressList[i].ToString();
                if (ip.Contains(".") && !ip.Equals("127.0.0.1")) ipAddressList.Add(ipHostInfo.AddressList[i]);
            }
            if (ipAddressList.Count == 1)
            {
                return ipAddressList[0];
            }
            else
            {
                int i = 0;
                foreach (IPAddress ipa in ipAddressList)
                {
                    Console.WriteLine($"[{i++}]: {ipa}");
                }
                System.Console.Write($"Opción [0-{t - ipAddressList.Count}]: ");
                string s = Console.ReadLine();
                if (Int32.TryParse(s, out int j))
                {
                    if ((j >= 0) && (j <= t))
                    {
                        return ipAddressList[j];
                    }
                }
                return null;
            }
        }

        public static void StartListening()
        {

            byte[] bytes = new Byte[TAM];

            IPAddress ipAddress = GetLocalIpAddress();
            if (ipAddress == null) return;
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, PORT);

            Socket listener = new Socket(ipAddress.AddressFamily,
                SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                while (true)
                {
                    Console.WriteLine("Waiting for a connection at {0}:{1} ...", ipAddress, PORT);
                    Socket handler = listener.Accept();

                    Message request = Receive(handler);

                    Console.WriteLine(request);//Print it

                    Message response = Process(request);

                    Send(handler, response);

                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            Console.WriteLine("\nPress ENTER to continue...");
            Console.Read();

        }

        public static void Send(Socket socket, Message message)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(Message));
            Stream stream = new MemoryStream();
            serializer.Serialize(stream, message);
            byte[] byteData = ((MemoryStream)stream).ToArray();
            // string xml = Encoding.ASCII.GetString(byteData, 0, byteData.Length);
            // Console.WriteLine(xml);//Imprime el texto enviado
            int bytesSent = socket.Send(byteData);
        }

        public static Message Receive(Socket socket)
        {
            byte[] bytes = new byte[TAM];
            int bytesRec = socket.Receive(bytes);
            string xml = Encoding.ASCII.GetString(bytes, 0, bytesRec);
            // Console.WriteLine(xml);//Imprime el texto recibido
            byte[] byteArray = Encoding.ASCII.GetBytes(xml);
            MemoryStream stream = new MemoryStream(byteArray);
            Message response = (Message)new XmlSerializer(typeof(Message)).Deserialize(stream);
            return response;
        }

        public static void AddMessage(Message message)
        {
            List<Message> lista;
            if (!repo.TryGetValue(message.To, out lista))
            {
                lista = new List<Message>();
                lista.Add(message);
                repo.Add(message.To, lista);
            }
            else
            {
                lista.Add(message);
            }
        }

        public static Message ListMessages(string toClient)
        {
            StringBuilder sb = new StringBuilder();
            List<Message> lista;
            if (repo.TryGetValue(toClient, out lista))
            {
                for (int i = 0; i < lista.Count; i++)
                {
                    sb.Append($"[{i}] From: {lista[i].From}\n");
                }
            }
            return new Message { From = "0", To = toClient, Msg = sb.ToString(), Stamp = "Server" };
        }

        public static Message RetrMessage(string toClient, int index)
        {
            Message msg = new Message { From = "0", To = toClient, Msg = "NOT FOUND", Stamp = "Server" };
            List<Message> lista;
            if (repo.TryGetValue(toClient, out lista))
            {
                if (index < lista.Count)
                {
                    msg = lista[index];
                    lista.RemoveAt(index);
                }
            }
            return msg;
        }

        // Se comprueba si se recibe una nueva clave pública y se verifican todos los mensajes recibidos
        public static Message Process(Message request)
        {
            Message response = new Message { From = "0", To = request.From, Msg = "ERROR", Stamp = "Server" };

            if (request.To == "0")
            {
                if (request.Msg.ToUpper().StartsWith("PUBKEY "))
                {
                    string pubKey = request.Msg.Substring(7);
                    if (Verify(request, pubKey))
                    {
                        string crt;
                        if (!crts.TryGetValue(request.From, out crt))
                        {
                            // Añadir el certificado
                            crts.Add(request.From, pubKey);
                            // Enviar la clave pública del servidor
                            response.Msg = X.RsaGetPubParsXml(rsa);
                        }
                        else
                        {
                            response.Msg = "ERROR impersonation";
                        }
                    }
                    else
                    {
                        response.Msg = "ERROR validation";
                    }
                }
                else if (request.Msg.ToUpper().StartsWith("LIST"))
                {
                    if (Verify(request))
                    {
                        response = ListMessages(request.From);
                    }
                    else
                    {
                        response.Msg = "ERROR validation";
                    }
                }
                else if (request.Msg.ToUpper().StartsWith("RETR "))
                {
                    if (Verify(request))
                    {
                        string s = request.Msg.ToUpper().Substring(5);
                        if (Int32.TryParse(s, out int index))
                        {
                            if (index >= 0)
                            {
                                response = RetrMessage(request.From, index);
                            }
                        }
                    }
                    else
                    {
                        response.Msg = "ERROR validation";
                    }
                }
            }
            else
            {
                if (Verify(request))
                {
                    AddMessage(request);
                    response = new Message { From = "0", To = request.From, Msg = "OK", Stamp = "Server" };
                }
                else
                {
                    response.Msg = "ERROR validation";
                }
            }
            // Firmar mensaje de respuesta
            Sign(ref response, rsa);
            return response;
        }

        public static int Main(String[] args)
        {
            StartListening();
            return 0;
        }
    }
}