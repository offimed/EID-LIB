 
## Belgian electronic identity card library (.NET Standard/.NET 10)

Dependencies:

- Middleware EID: https://eid.belgium.be/fr

Works with:
- Windows (32 bits)
- Mac (64 bits)
- Linux (64 bits)
- ARM Compatible => Middleware

If you would have a build for Windows, you need to build EID-Lib with Windows. (Because I use a preprocessor directive for use 32 bits long types)

For Xamarin Mac, if you have to use the Sandbox mode and change the language in "/usr/local/etc/beid.conf" (Shared by all users), you have to edit "Entitlements.plist" with (discouraged): 
- key: com.apple.security.temporary-exception.files.absolute-path.read-write  (Not allowed by app store)
- string value: /usr/local/etc/BEID.conf
It's for set the language in Settings.SetLanguage. 
Documentation: https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html

For Linux/Mac, if /usr/local/etc/beid.conf creation/update fail (authorization, sandbox mode, ...), this file will used:

- Mac: $HOME/Library/Preferences/beid.conf
- Linux: $HOME/.config/beid.conf

More information: https://downloads.services.belgium.be/eid/eID3_configparameters.pdf 