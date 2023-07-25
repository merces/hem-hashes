# Hashes

[HIEW](https://hiew.ru) External Module (HEM) to calculate MD5, SHA-1, and SHA-256 hashes of files and blocks.

## Installation

Download the `.hem` file and put it in your HIEW `hem` folder.

## Usage

After opening a file in HIEW, press `F11` to load a HIEW module and choose it from the menu.
It will calculate common hashes of the whole file. If you mark a block instead, Hashes will generate
the hashes of the block content. Press `F5` to copy a hash value to clipboard.

### Example

```
 00000000:  4D 5A 90 00-03 00 00 00-04 00 00 00-FF FF 00 00  MZÉ                                                       
 00000010:  B8 00 00 00-00 00 00 00-40 00 00 00-00 00 00 00  +       @                                                 
 00000020:  00 00 00 00-00 00 00 00-00 00 00 00-00 00 00 00                                                            
 00000030:  00 00 00 00-00 00 00 00-00 00 00 00-08 01 00 00                                                            
 00000040:  0E 1F BA 0E-00 B4 09 CD-21 B8 01 4C-CD 21 54 68    ¦  ¦ -!+ L-!Th                                          
 00000050:  69 73 20 70-72 6F 67 72-61 6D 20 63-61 6E 6E 6F  is program canno                                          
 00000060:  74 20 62 65-20 72 75 6E-20 69 6E 20-44 4F 53 20  t be run in DOS                                           
 00000070:  6D 6F 64 65-2E 0D 0D 0A-24 00 00 00-00 00 00 00  mode.   $                                                 
 00000080:  0D 15 A4 8B-49 74 CA D8-49 74 CA D8-49 74 CA D8    ñïIt-+It-+It-+                                          
 00000090:  02 0C C9 D9-43 74 CA D8-02 0C CF D9-C0 74 CA D8    ++Ct-+  -++t-+                                          
 000000A0:  02 0C CE D9-5D 74 CA D8-ED 0A CF D9-56 74 CA D8    ++]t-+f -+Vt-+                                          
 000000B0:  ED 0A CE D9                                                                     [x]                        
 000000C0:  02 0C CB D9  +-------------------Hashes (MD5, SHA-1, SHA-256)-------------------+                          
 000000D0:  43 0B C2 D9  ¦ e9efd037af3bfde9c1a85c1cc523adbf                                 ¦                          
 000000E0:  43 0B C8 D9  ¦ f48e7ea68210c362636b28712be5c3b6117be035                         ¦                          
 000000F0:  00 00 00 00  ¦ c39ef9378f8ca5799638f95db22b34176f63bfbc417784a5c21b957008a999a4 ¦                          
 00000100:  00 00 00 00  +------------------------------------------------------------------+                          
 00000110:  DD 40 40 64                                                                                                
 00000120:  0B 01 0E 24-00 2A 01 00-00 9A 00 00-00 00 00 00     $ *   Ü                                                
 00000130:  E0 13 00 00-00 10 00 00-00 40 01 00-00 00 00 10  a        @                                                
 00000140:  00 10 00 00-00 02 00 00-06 00 00 00-00 00 00 00                                                            
 00000150:  06 00 00 00-00 00 00 00-00 00 02 00-00 04 00 00                                                            
 00000160:  00 00 00 00-02 00 40 41-00 00 10 00-00 10 00 00        @A                                                  
 00000170:  00 00 10 00-00 10 00 00-00 00 00 00-10 00 00 00                                                            
 00000180:  10 A9 01 00-48 00 00 00-58 A9 01 00-50 00 00 00   ¬  H   X¬  P                                             
 00000190:  00 00 00 00-00 00 00 00-00 00 00 00-00 00 00 00                                                            
 000001A0:  00 00 00 00-00 00 00 00-00 E0 01 00-64 11 00 00           a  d                                             
 000001B0:  70 9D 01 00-70 00 00 00-00 00 00 00-00 00 00 00  p¥  p                                                     
```

## Thanks

- @taviso for his [kiewtai module](https://github.com/taviso/kiewtai) (I borrowed code from there, but inserted
my own bugs :cowboy_hat_face:).
- SEN for HIEW.

## Author

Fernando Mercês - @mer0x36
