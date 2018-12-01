/*
 *  Managed C# wrapper for Hydrogen cryptographic library by Frank Denis 
 *  Copyright (c) 2018 Stanislav Denisov
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace Hydrogen {
	[StructLayout(LayoutKind.Sequential)]
	public struct KeyPair {
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
		public byte[] publicKey;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
		public byte[] secretKey;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SessionKeyPair {
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
		public byte[] receiveKey;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
		public byte[] sendKey;
	}

	public static class Library {
		public const int hashKeyBytes = 32;
		public const int hashBytesMin = 16;
		public const int hashBytesMax = 65535;
		public const int masterKeyBytes = 32;
		public const int storedBytes = 128;
		public const int headerBytes = 20 + 16;
		public const int secretKeyBytes = 32;
		public const int probeBytes = 16;
		public const int packetBytes = 32;

		public static bool Initialize() {
			return Native.hydro_init() == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static uint Random() {
			return Random(0);
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static uint Random(uint upperBound) {
			if (upperBound > 0)
				return Native.hydro_random_uniform(upperBound);

			return Native.hydro_random_u32();
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static void HashKeygen(byte[] key) {
			if (key.Length != Library.hashKeyBytes)
				throw new ArgumentOutOfRangeException();

			Native.hydro_hash_keygen(key);
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Hash(byte[] hash, int hashLength, byte[] message, int messageLength, string context) {
			if (hashLength < 0 || messageLength < 0 || hashLength < Library.hashBytesMin || hashLength > Library.hashBytesMax)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_hash_hash(hash, (IntPtr)hashLength, message, (IntPtr)messageLength, context, IntPtr.Zero) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Hash(byte[] hash, int hashLength, byte[] message, int messageLength, string context, byte[] key) {
			if (hashLength < 0 || messageLength < 0 || hashLength < Library.hashBytesMin || hashLength > Library.hashBytesMax)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_hash_hash(hash, (IntPtr)hashLength, message, (IntPtr)messageLength, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static void MasterKeygen(byte[] key) {
			if (key.Length != Library.masterKeyBytes)
				throw new ArgumentOutOfRangeException();

			Native.hydro_pwhash_keygen(key);
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool DeterministicKey(byte[] key, int keyLength, string password, int passwordLength, string context, byte[] masterKey, ulong iterationsLimit, int memoryLimit, byte threads) {
			if (keyLength < 0 || passwordLength < 0 || memoryLimit < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_pwhash_deterministic(key, (IntPtr)keyLength, password, (IntPtr)passwordLength, context, masterKey, iterationsLimit, (IntPtr)memoryLimit, threads) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool StorageKey(byte[] key, string password, int passwordLength, byte[] masterKey, ulong iterationsLimit, int memoryLimit, byte threads) {
			if (passwordLength < 0 || memoryLimit < 0 || key.Length != Library.storedBytes)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_pwhash_create(key, password, (IntPtr)passwordLength, masterKey, iterationsLimit, (IntPtr)memoryLimit, threads) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool VerifyKey(byte[] key, string password, int passwordLength, byte[] masterKey, ulong iterationsLimit, int memoryLimit, byte threads) {
			if (passwordLength < 0 || memoryLimit < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_pwhash_verify(key, password, (IntPtr)passwordLength, masterKey, iterationsLimit, (IntPtr)memoryLimit, threads) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool ReencryptKey(byte[] key, byte[] masterKey, byte[] newMasterKey) {
			return Native.hydro_pwhash_reencrypt(key, masterKey, newMasterKey) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool UpgradeKey(byte[] key, byte[] masterKey, ulong iterationsLimit, int memoryLimit, byte threads) {
			if (memoryLimit < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_pwhash_upgrade(key, masterKey, iterationsLimit, (IntPtr)memoryLimit, threads) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static void ExchangeKeygen(out KeyPair keyPair) {
			Native.hydro_kx_keygen(out keyPair);
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool N1(out SessionKeyPair sessionKeyPair, byte[] packet, byte[] publicKey) {
			return Native.hydro_kx_n_1(out sessionKeyPair, packet, IntPtr.Zero, publicKey) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool N2(out SessionKeyPair sessionKeyPair, byte[] packet, ref KeyPair keyPair) {
			return Native.hydro_kx_n_2(out sessionKeyPair, packet, IntPtr.Zero, ref keyPair) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static void SecretKeygen(byte[] key) {
			if (key.Length != Library.secretKeyBytes)
				throw new ArgumentOutOfRangeException();

			Native.hydro_secretbox_keygen(key);
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Encrypt(IntPtr packet, byte[] message, int messageLength, string context, byte[] key) {
			if (messageLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_encrypt(packet, message, messageLength, 0, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Encrypt(byte[] packet, byte[] message, int messageLength, string context, byte[] key) {
			if (messageLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_encrypt(packet, message, messageLength, 0, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Decrypt(byte[] message, IntPtr packet, int packetLength, string context, byte[] key) {
			if (packetLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_decrypt(message, packet, packetLength, 0, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool Decrypt(byte[] message, byte[] packet, int packetLength, string context, byte[] key) {
			if (packetLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_decrypt(message, packet, packetLength, 0, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool CreateProbe(byte[] probe, byte[] cipher, int cipherLength, string context, byte[] key) {
			if (probe.Length != Library.probeBytes || cipherLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_probe_create(probe, cipher, (IntPtr)cipherLength, context, key) == 0;
		}

		#if HYDROGEN_INLINING
			[MethodImpl(256)]
		#endif
		public static bool VerifyProbe(byte[] probe, byte[] cipher, int cipherLength, string context, byte[] key) {
			if (probe.Length != Library.probeBytes || cipherLength < 0)
				throw new ArgumentOutOfRangeException();

			return Native.hydro_secretbox_probe_verify(probe, cipher, (IntPtr)cipherLength, context, key) == 0;
		}
	}

	[SuppressUnmanagedCodeSecurity]
	internal static class Native {
		#if __IOS__ || UNITY_IOS && !UNITY_EDITOR
			private const string nativeLibrary = "__Internal";
		#else
			private const string nativeLibrary = "hydrogen";
		#endif

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_init();

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern uint hydro_random_u32();

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern uint hydro_random_uniform(uint upperBound);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void hydro_hash_keygen(byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_hash_hash(byte[] hash, IntPtr hashLength, byte[] message, IntPtr messageLength, string context, IntPtr key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_hash_hash(byte[] hash, IntPtr hashLength, byte[] message, IntPtr messageLength, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void hydro_pwhash_keygen(byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_pwhash_deterministic(byte[] key, IntPtr keyLength, string password, IntPtr passwordLength, string context, byte[] masterKey, ulong iterationsLimit, IntPtr memoryLimit, byte threads);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_pwhash_create(byte[] key, string password, IntPtr passwordLength, byte[] masterKey, ulong iterationsLimit, IntPtr memoryLimit, byte threads);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_pwhash_verify(byte[] key, string password, IntPtr passwordLength, byte[] masterKey, ulong iterationsLimit, IntPtr memoryLimit, byte threads);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_pwhash_reencrypt(byte[] key, byte[] masterKey, byte[] newMasterKey);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_pwhash_upgrade(byte[] key, byte[] masterKey, ulong iterationsLimit, IntPtr memoryLimit, byte threads);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void hydro_kx_keygen(out KeyPair keyPair);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_kx_n_1(out SessionKeyPair sessionKeyPair, byte[] packet, IntPtr secretKey, byte[] publicKey);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_kx_n_2(out SessionKeyPair sessionKeyPair, byte[] packet, IntPtr secretKey, ref KeyPair keyPair);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern void hydro_secretbox_keygen(byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_encrypt(IntPtr packet, byte[] message, int messageLength, ulong messageID, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_decrypt(byte[] message, IntPtr packet, int packetLength, ulong messageID, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_encrypt(byte[] packet, byte[] message, int messageLength, ulong messageID, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_decrypt(byte[] message, byte[] packet, int packetLength, ulong messageID, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_probe_create(byte[] probe, byte[] cipher, IntPtr cipherLength, string context, byte[] key);

		[DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
		internal static extern int hydro_secretbox_probe_verify(byte[] probe, byte[] cipher, IntPtr cipherLength, string context, byte[] key);
	}
}
