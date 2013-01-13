VASCO VACMAN Controller
======================

VACMAN Controller is a state-of-the-art API-based authentication platform that serves as a back-end for DIGIPASS strong authentication. It automatically processes login requests to ensure only properly authenticated users obtain access to protected online applications. A unique design, unlimited scalability and versatile flexibility make VACMAN Controller a perfect fit for large deployments in a variety of customer interfacing applications. Benchmarked at 9,000+ authentications per second, it is capable of processing heavy volumes of authentication requests and can support mass deployments in applications such as online banking, e-commerce, online gaming, web portals and more.

VACMAN Controller offers flexibility unmatched by any other competitor in the industry:
Flexible API

VACMAN Controller is a flexible API-based solution that provides strong security with minimal impact to your existing infrastructure. Simply link VACMAN Controller to your authentication application, and it automatically processes login requests.

Support for Multiple Form Factors

VACMAN Controller is a unique and flexible platform that supports multiple authentication devices and mechanisms. It works with all hardware- and software-based DIGIPASS authenticators as well as OATH-compliant devices and EMV-CAP smart cards. When combined with DIGIPASS hardware and software authenticators, VACMAN Controller can provide end-to-end secure online provisioning and management of these authenticators.

The following form factors are supported in every implementation:

One-button hardware authenticators
Software authentication
Mobile authentication
SMS delivery (Requires integration of an SMS gateway)
USB authenticators
Smart cards
Support for Multiple Authentication Technologies

VACMAN Controller supports a range of authentication modes including:

one-time passwords (response only)
Challenge/response
Electronic signatures
Strong and remote host authentication

Installation
------------

Get Vacman Controller library at www.vasco.com and install. It should create 
/opt/vasco/VACMAN_Controller-3.11.2/lib/libaal2sdk-3.11.2.so. 

Then 

  rake install 

will install the gem. Then you can check it works by 

  rspec


  