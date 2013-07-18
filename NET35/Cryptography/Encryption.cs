/******************************************************************************
*	Copyright 2013 Prospective Software Inc.
*	Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*	You may obtain a copy of the License at
*
*		http://www.apache.org/licenses/LICENSE-2.0
*
*	Unless required by applicable law or agreed to in writing, software
*	distributed under the License is distributed on an "AS IS" BASIS,
*	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*	See the License for the specific language governing permissions and
*	limitations under the License.
******************************************************************************/

/******************************************************************************
*	Copyright 2013 Prospective Software Inc.
*	Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*	You may obtain a copy of the License at
*
*		http://www.apache.org/licenses/LICENSE-2.0
*
*	Unless required by applicable law or agreed to in writing, software
*	distributed under the License is distributed on an "AS IS" BASIS,
*	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*	See the License for the specific language governing permissions and
*	limitations under the License.
******************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace System.Utilities.Cryptography
{
	/// <summary>
	/// Provides encryption and decryption capabilites using 128-bit, 192-bit, and 256-bit AES encryption methods.
	/// This implementation is FIPS compliant.
	/// </summary>
	public static class Encryption
	{
		private const int Bits128 = 16;
		private const int Bits192 = 24;
		private const int Bits256 = 32;

		public static string ConvertToUnsecureString(System.Security.SecureString securePassword)
		{
			if (securePassword == null)
				throw new ArgumentNullException("securePassword");

			IntPtr unmanagedString = IntPtr.Zero;
			try
			{
				unmanagedString = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(securePassword);
				return System.Runtime.InteropServices.Marshal.PtrToStringUni(unmanagedString);
			}
			finally
			{
				System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
			}
		}

		#region - Key Generation Functions -

		private struct KeyData
		{
			public byte[] Key;
			public byte[] IV;
		}

		//Computes an 128-bit Initialization Vector
		private static KeyData GenerateKeyIV128(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits128];
			for (int i = 0; i < Bits128; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits128)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits128;
				while (TempKey.Count != Bits128)
				{
					if (TempKey.Count < Bits128)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits128)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits128;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData { Key = Key, IV = IV };
			return NK;
		}

		//Computes an 192-bit Initialization Vector
		private static KeyData GenerateKeyIV192(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits192];
			for (int i = 0; i < Bits192; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits192)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits192;
				while (TempKey.Count != Bits192)
				{
					if (TempKey.Count < Bits192)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits192)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits192;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData { Key = Key, IV = IV };
			return NK;
		}

		//Computes an 256-bit Initialization Vector
		private static KeyData GenerateKeyIV256(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits256];
			for (int i = 0; i < Bits256; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits256)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits256;
				while (TempKey.Count != Bits256)
				{
					if (TempKey.Count < Bits256)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits256)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits256;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData{ Key = Key, IV = IV };
			return NK;
		}

		#endregion

		#region - 128-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128Byte(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt128Stream(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128Byte(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt128Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt128Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64Secure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128ByteSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt128StreamSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt128String(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);
	
				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt128String(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);
	
				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt128Byte(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt128Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt128Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt128Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt128StringSecure(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS, System.Text.Encoding.UTF8);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt128StringSecure(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 128, KeySize = 128, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		#endregion

		#region - 192-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192Byte(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt192Stream(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192Byte(byte[] Data, byte[] Key)
		{
			//Get the IV and length corrected Key.
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

			return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt192Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt192Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64Secure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192ByteSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt192StreamSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt192String(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt192String(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt192Byte(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt192Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt192Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt192Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt192StringSecure(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS, System.Text.Encoding.UTF8);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt192StringSecure(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 192, KeySize = 192, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		#endregion

		#region - 256-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256Byte(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt256Stream(string Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(System.Text.Encoding.Default.GetBytes(Data), 0, System.Text.Encoding.Default.GetByteCount(Data));
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256Byte(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt256Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				CS.Write(Data, 0, Data.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt256Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			BinaryReader DR = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				DR = new BinaryReader(Data);
				var D = new byte[DR.BaseStream.Length];
				DR.Read(D, 0, (int)DR.BaseStream.Length - 1);
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
				if (DR != null) DR.Close();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64Secure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return Convert.ToBase64String(MS.ToArray());
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256ByteSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS.ToArray();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted. Must be UTF8.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A stream containing the encoded data.</returns>
		public static Stream Encrypt256StreamSecure(System.Security.SecureString Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream();
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateEncryptor(), CryptoStreamMode.Write);

				byte[] D = System.Text.Encoding.UTF8.GetBytes(ConvertToUnsecureString(Data));
				CS.Write(D, 0, D.Length);
				CS.FlushFinalBlock();

				return MS;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				MS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt256String(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt256String(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				return DS.ReadToEnd();
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt256StringSecure(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS, System.Text.Encoding.UTF8);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted. Will be converted to UTF8.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static System.Security.SecureString Decrypt256StringSecure(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			StreamReader DS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);
				DS = new StreamReader(CS);

				var ss = new System.Security.SecureString();
				while (DS.EndOfStream == false)
					ss.AppendChar(Convert.ToChar(DS.Read()));
				ss.MakeReadOnly();
				return ss;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
				if (DS != null) DS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt256Byte(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt256Byte(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return D;
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt256Stream(byte[] Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			var MS = new MemoryStream(Data);
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(MS, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				MS.Dispose();
				if (CS != null) CS.Dispose();
			}
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static Stream Decrypt256Stream(Stream Data, byte[] Key)
		{
			AesCryptoServiceProvider AES = null;
			CryptoStream CS = null;
			try
			{
				//Get the IV and length corrected Key.
				KeyData KeyData = GenerateKeyIV128(Key);
				//Create the AES crytpograhy object.
				AES = new AesCryptoServiceProvider { BlockSize = 256, KeySize = 256, Key = KeyData.Key, IV = KeyData.IV, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
				CS = new CryptoStream(Data, AES.CreateDecryptor(), CryptoStreamMode.Read);

				var D = new byte[CS.Length];
				CS.Read(D, 0, (int)CS.Length - 1);
				return new MemoryStream(D);
			}
			finally
			{
				if (AES != null) AES.Clear();
				if (CS != null) CS.Dispose();
			}
		}

		#endregion
	}
}