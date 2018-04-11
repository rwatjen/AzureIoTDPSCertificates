using McMaster.Extensions.CommandLineUtils;
using System;

namespace RW.DPSCertificateTool
{
    [Subcommand("createdevicecert", typeof(CreateDeviceCert))]
    [Subcommand("createcertchain", typeof(CreateCertChain))]
    [Subcommand("createverificationcert", typeof(CreateVerificationCert))]
    [HelpOption(ShowInHelpText = false)]
    class Program
    {
        static int Main(string[] args) => CommandLineApplication.Execute<Program>(args);

        public string[] RemainingArgs { get; set; }

        private int OnExecute()
        {
            Console.Error.WriteLine("No command passed on the command line. Run with --help to see command line options.");
            return -1;
        }
    }
}
