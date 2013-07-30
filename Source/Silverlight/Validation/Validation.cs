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

using System.Text.RegularExpressions;

namespace System.Utilities
{
	/// <summary>
	/// Provides several functions for validating various inputs.
	/// </summary>
	public static class Validation
	{
		private static readonly Regex MatchFileName;
		private static readonly Regex MatchHTTPURI;
		private static readonly Regex MatchIPv4;
		private static readonly Regex MatchIPv6;
		private static readonly Regex MatchEmail;
		private static readonly Regex MatchPhone1;
		private static readonly Regex MatchPhone2;
		private static readonly Regex MatchZIP;
		private static readonly Regex MatchZIP5;
		private static readonly Regex MatchAlphaNumeric;
		private static readonly Regex MatchNumeric;

		static Validation()
		{
			MatchFileName = new Regex(@"^[^ \\/:*?""<>|]+([ ]+[^ \\/:*?""<>|]+)*$", RegexOptions.IgnoreCase | RegexOptions.Singleline);
			MatchHTTPURI = new Regex(@"^(http|https)\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*$", RegexOptions.Singleline);
			MatchIPv4 = new Regex(@"^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$", RegexOptions.Singleline);
			MatchIPv6 = new Regex(@"^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$", RegexOptions.Singleline);
			MatchEmail = new Regex(@"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$", RegexOptions.Singleline | RegexOptions.IgnoreCase);
			MatchPhone1 = new Regex("^(1\\s*[-\\/\\.]?)?(\\((\\d{3})\\)|(\\d{3}))\\s*[-\\/\\.]?\\s*(\\d{3})\\s*[-\\/\\.]?\\s*(\\d{4})\\s*(([xX]|[eE][xX][tT])\\.?\\s*(\\d+))*$", RegexOptions.Singleline);
			MatchPhone2 = new Regex("^([\\(]?(?<AreaCode>[0-9]{3})[\\)]?)?[ \\.\\-]?(?<Exchange>[0-9]{3})[ \\.\\-](?<Number>[0-9]{4})$", RegexOptions.Singleline);
			MatchZIP = new Regex("^\\d{5}(?:[-\\s]\\d{4})?$", RegexOptions.Singleline);
			MatchZIP5 = new Regex("^\\d{5}$", RegexOptions.Singleline);
			MatchAlphaNumeric = new Regex("^[a-zA-Z0-9]", RegexOptions.Singleline);
			MatchNumeric = new Regex("^[0-9]", RegexOptions.Singleline);
		}

		/// <summary>
		/// Tests whether input string is a valid phone number.
		/// </summary>
		/// <param name="FileName">Phone number to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidFileName(string FileName)
		{
			return MatchFileName.IsMatch(FileName);
		}

		/// <summary>
		/// Tests whether input string is a valid phone number.
		/// </summary>
		/// <param name="HTTPURI">Phone number to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidHTTPURI(string HTTPURI)
		{
			return MatchHTTPURI.IsMatch(HTTPURI);
		}

		/// <summary>
		/// Tests whether input string is a valid phone number.
		/// </summary>
		/// <param name="IPv4">Phone number to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidIPv4(string IPv4)
		{
			return MatchIPv4.IsMatch(IPv4);
		}

		/// <summary>
		/// Tests whether input string is a valid phone number.
		/// </summary>
		/// <param name="IPv6">Phone number to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidIPv6(string IPv6)
		{
			return MatchIPv6.IsMatch(IPv6);
		}

		/// <summary>
		/// Tests whether input string is a valid phone number.
		/// </summary>
		/// <param name="PhoneNumber">Phone number to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidPhoneNumber(string PhoneNumber)
		{
			return MatchPhone1.IsMatch(PhoneNumber) || MatchPhone2.IsMatch(PhoneNumber);
		}

		/// <summary>
		/// Tests whether input string is a valid email address.
		/// </summary>
		/// <param name="EmailAddress">Email address to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidEmailAddress(string EmailAddress)
		{
			return MatchEmail.IsMatch(EmailAddress);
		}

		/// <summary>
		/// Tests whether input string is a valid 5 or 9 digit ZIP Code.
		/// Expected format: #####, ##### ####, or #####-####.
		/// </summary>
		/// <param name="ZIP">5 or 9 digit ZIP code to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidZIP(string ZIP)
		{
			return MatchZIP.IsMatch(ZIP);
		}

		/// <summary>
		/// Tests whether input string is a valid 5 digit ZIP Code.
		/// </summary>
		/// <param name="ZIP5">5 digit ZIP Code to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsValidZIP5(string ZIP5)
		{
			return MatchZIP5.IsMatch(ZIP5);
		}

		/// <summary>
		/// Tests whether input string contains valid alpha-numeric characters.
		/// </summary>
		/// <param name="stringToCheck">String to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsAlphaNumeric(String stringToCheck)
		{
			return MatchAlphaNumeric.IsMatch(stringToCheck);
		}

		/// <summary>
		/// Tests whether input string contains valid numeric characters.
		/// </summary>
		/// <param name="stringToCheck">String to test.</param>
		/// <returns>Boolean success or fail.</returns>
		public static bool IsNumeric(String stringToCheck)
		{
			return MatchNumeric.IsMatch(stringToCheck);
		}
	}
}