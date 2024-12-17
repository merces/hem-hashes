# Hashes

[Hiew](https://hiew.io) External Module (HEM) to calculate CRC-32, MD5, SHA-1, and SHA-256 hashes of files and blocks.

## Installation

Download the `.hem` file and put it in your Hiew `hem` folder.

## Usage

After opening a file in Hiew, press `F11` to load a Hiew module and choose it from the menu.
It will calculate common hashes of the whole file. If you mark a block instead, Hashes will generate
the hashes of the block content. Press `F5` to copy a hash value to clipboard.

### Example

![](assets/hem-hashes.gif)

## Requirements

- Licensed version of Hiew.
- Windows Vista or newer.

### Note for Windows XP users

It is possible to use Hashes with it, but you need the following:

- Visual C++ Redistributable for Visual Studio v16.7.
Download it from [here](https://my.visualstudio.com/downloads) (requires a Microsoft account).
- `bcrypt.dll` in Hiew's folder or any other folder listed in `%PATH%`.
There's an open source implementation [here](https://github.com/Blaukovitch/bcrypt-XP).

## Thanks

- @taviso for his [kiewtai module](https://github.com/taviso/kiewtai) (I borrowed code from there, but inserted
my own bugs :cowboy_hat_face:).
- SEN for Hiew.

## Author

Fernando Mercês - @mer0x36
