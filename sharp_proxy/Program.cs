using System;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.Examples.Basic.Helpers;

namespace Sharp.Proxy
{
    internal class Program
    {

        private static readonly ProxyController controller = new ProxyController();

        static void Main(string[] args)
        {
            ConsoleHelper.DisableQuickEditMode();

            controller.StartProxy();

            Console.WriteLine("Press any key to exit...");
            Console.WriteLine();
            Console.Read();

            controller.Stop();
        }
    }
}
