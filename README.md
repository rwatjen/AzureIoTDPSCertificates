# Azure IoT Hub DPS Certificates
Sample app to create X.509 certificates for [Azure IoT Hub Device Provisioning Service](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps).

This repository contains a .NET Core 2.0 command line app, which can be used to create an X.509 certificate chain and device certificates for use with the Azure IoT Hub Device Provisioning Service.

The code in this repository was developed in my spare time. If you have problems or questions, feel free to add them under Issues, but be prepared to wait for answers. As mentioned, this is a hobby project that I work on in my spare time.

### Further reading
To read more about the details and the reason the app does what it does, 
please see the accompanying blog posts:

* [Azure IoT Hub Device Provisioning with group enrollments](https://blog.rassie.dk/2018/04/azure-iot-hub-device-provisioning-with-group-enrollments/)
* [Using Azure IoT Hub Device Provisioning Service to provision a device](https://blog.rassie.dk/2018/04/using-azure-iot-hub-device-provisioning-service-to-provision-a-device/)
* [Creating an X.509 Certificate Chain in C#](https://blog.rassie.dk/2018/04/creating-an-x-509-certificate-chain-in-c)

### Important notice
If you don't have experience with X.509 certificates, Certificate Authorities, 
etc. then you **should not** to build your own CA infrastructure.

The code in this repository is a sample app that fulfills my needs for testing 
the Azure IoT Hub Device Provisioning Service. It is by no means a replacement 
for a real X.509 certificate infrastructure.

### How to use the sample app
The app is a .NET Core 2.0 Console application.
The easiest way to run it is to clone the repository, and open a command prompt 
in that directory.

There are a number of command line switches. See the usage by running
```
dotnet run -- --help
```
```
Usage: RW.DPSCertificateTool [command]

Commands:
  createcertchain
  createdevicecert
  createverificationcert

Run 'RW.DPSCertificateTool [command] --help' for more information about a command.
```

If you want to create a new certificate authority chain with a number of intermediates, run
```
dotnet run -- createcertchain --help
```

This will output the options that are available for that operation:
```
Usage: RW.DPSCertificateTool createcertchain [options]

Options:
  -?|-h|--help  Show help information
  -s            The generated root CA's certificate subject name. This will also be the base of the generated filenames.
  -p            The password of the PFX file(s) that are output.
  -i            The number of intermediate CAs to create in a chain.
```

In general, you can add `--help` to all the operations to see their options.

To create a new Root CA and an intermediate chain run
```
dotnet run -- createcertchain -s "My cool CA" -p securepassword -i 5
```

This will create a root CA with the subject "My cool CA", where the private 
key is protected with the password "securepassword", and there will be 5 
intermediate CAs. The intermediate CA's passwords are also "securepassword".

The command has generated these files in the current directory:
```
10-04-2018  22:15             1.563 Intermediate 1.pfx
10-04-2018  22:15             2.107 Intermediate 2.pfx
10-04-2018  22:15             2.659 Intermediate 3.pfx
10-04-2018  22:15             3.203 Intermediate 4.pfx
10-04-2018  22:15             3.755 Intermediate 5.pfx
10-04-2018  22:15               414 My cool CA.cer
10-04-2018  22:15             1.027 My cool CA.pfx
```

### IoT Hub DPS Verification certificate
You can use the generated "My cool CA.cer" file for the IoT Hub DPS. After 
uploading it, you must verify that you can actually create certificates
signed by that root CA.

The Azure portal will present a verification code. That must be the subject of
a new leaf/device certificate that has been signed by the root CA.

This tool will let you create a verification certificate with the command line
```
dotnet run -- createverificationcert -s "<long verification ID>" -c "My cool CA.pfx" -p "securepassword"
```
*Don't just copy/paste the above. The certificate subject must also be a valid DNS name. Use the verification ID from the portal from your DPS instance.*

After loading the Root CA PFX file, the tool will output a new `.cer` file 
named after the verification ID.

That `.cer` file must be uploaded to the Azure Portal to verify you ownership 
of the root CA certificate.

### IoT Hub DPS device certificate
It's also possible to create device certificates.

Since one of the purposes of my testing was to use an intermediate CA to issue 
device certificates, you can pass any PFX file containg a CA certificate on 
the command line when creating a device certificate:

```
dotnet run -- createdevicecert -s "mydevicecert" -p "mysecuredevicepassword" -c "Intermediate 5.pfx" -q "securepassword"
```
Note that you need to pass both a password for the newly created "mydevicecert" certificate as well as the password to open the PFX file.

This command creates a file called `mydevicecert.pfx`, which can be used 
when connecting to IoT Hub DPS. The PFX file will contain a private and public 
key for the device, as well as the public parts of the intermediates and root 
in the entire chain of trust.
