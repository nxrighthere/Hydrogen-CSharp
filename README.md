<p align="center"> 
  <img src="https://i.imgur.com/VsCHqUk.png" alt="alt logo">
</p>

[![PayPal](https://drive.google.com/uc?id=1OQrtNBVJehNVxgPf6T6yX1wIysz1ElLR)](https://www.paypal.me/nxrighthere) [![Bountysource](https://drive.google.com/uc?id=19QRobscL8Ir2RL489IbVjcw3fULfWS_Q)](https://salt.bountysource.com/checkout/amount?team=nxrighthere) [![Discord](https://discordapp.com/api/guilds/515987760281288707/embed.png)](https://discord.gg/ceaWXVw)

This repository provides a managed C# wrapper for [Hydrogen](https://github.com/jedisct1/libhydrogen) cryptographic library which is created and maintained by [Frank Denis](https://github.com/jedisct1). You will need to [build](https://github.com/jedisct1/libhydrogen/wiki/Installation#downloading-the-source-code) the native library before you get started.

Usage
--------
Before starting to work, the library should be initialized using `Hydrogen.Library.Initialize();` function.

##### Generate random data:
```c#
// Unbounded
uint data = Hydrogen.Library.Random();

// Bounded
uint upperBound = 1000000;
uint data = Hydrogen.Library.Random(upperBound);
```

##### Declare a new context:
```c#
// Only the first 8 characters will be used
string context = "hydrocontext";
```

##### Generic hashing:
```c#
string message = "Arbitrary data to hash";
byte[] data = Encoding.ASCII.GetBytes(message);;
int hashLength = 16;
byte[] hash = new byte[hashLength]; // Storage for hash

// Without a key
if (Hydrogen.Library.Hash(hash, hashLength, data, data.Length, context))
	Console.WriteLine("Hash successfully generated!");
  
// With a key
byte[] hashKey = new byte[Hydrogen.Library.hashKeyBytes];

Hydrogen.Library.HashKeygen(hashKey);

if (Hydrogen.Library.Hash(hash, hashLength, data, data.Length, context, hashKey))
	Console.WriteLine("Hash successfully generated using key!");
```

##### Password hashing:
```c#
string password = "feelsgoodman";
byte[] masterKey = new byte[Hydrogen.Library.masterKeyBytes];
int keyLength = 32;
byte[] key = new byte[keyLength]; // Storage for high-entropy key

// Generate master key
Hydrogen.Library.MasterKeygen(masterKey);

// Generate high-entropy key from a password using master key
if (Hydrogen.Library.DeterministicKey(key, keyLength, password, password.Length, context, masterKey, 1000, 1024, 1))
	Console.WriteLine("High-entropy key successfully generated!");

// Generate authenticated representative of the password to store in the database
byte[] storedKey = new byte[Hydrogen.Library.storedBytes];

if (Hydrogen.Library.StorageKey(storedKey, password, password.Length, masterKey, 1000, 1024, 1))
	Console.WriteLine("Authenticated representative successfully generated!");

// Verify stored key
if (Hydrogen.Library.VerifyKey(storedKey, password, password.Length, masterKey, 1000, 1024, 1))
	Console.WriteLine("Stored key successfully verified!");
  
// Reencrypt stored key
byte[] newMasterKey = new byte[Hydrogen.Library.masterKeyBytes];

Hydrogen.Library.MasterKeygen(newMasterKey);

if (Hydrogen.Library.ReencryptKey(storedKey, masterKey, newMasterKey))
	Console.WriteLine("Stored key successfully reencrypted!");
  
// Upgrade stored key
if (Hydrogen.Library.UpgradeKey(storedKey, newMasterKey, 2000, 1024, 2))
	Console.WriteLine("Stored key successfully upgraded!");
```

##### Secure network communication based on Noise protocol:
```c#

```

API reference
--------
