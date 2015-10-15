// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using System.Security.Authentication.ExtendedProtection;
using SafeSslHandle = Interop.libssl.SafeSslHandle;

internal static partial class Interop
{
    internal static class ChannelBinding
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct Bindings
        {
            internal int length;
            internal IntPtr pBindings;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SEC_CHANNEL_BINDINGS
        {
            internal Int32 dwInitiatorAddrType;
            internal Int32 cbInitiatorLength;
            internal Int32 dwInitiatorOffset;
            internal Int32 dwAcceptorAddrType;
            internal Int32 cbAcceptorLength;
            internal Int32 dwAcceptorOffset;
            internal Int32 cbApplicationDataLength;
            internal Int32 dwApplicationDataOffset;
        }

        private static readonly byte[] tlsServerEndPointByteArray = System.Text.Encoding.UTF8.GetBytes("tls-server-end-point:");
        private static readonly byte[] TlsUniqueByteArray = System.Text.Encoding.UTF8.GetBytes("tls-unique:");
        private const int HashMaxLength = 128;
        private static int cbStructSize = -1;

        private static int secChannelBindingSize
        {
            get
            {
                if (cbStructSize < 0)
                {
                    unsafe
                    {
                        cbStructSize = sizeof(SEC_CHANNEL_BINDINGS);
                    }
                }

                return cbStructSize;
            }
        }

        internal static void getEndPointChannelBindings(SafeSslHandle context, ChannelBindingKind attribute, out Bindings bindingsObj)
        {
            int certHashSize = 0;

            int tlsServerEndPointByteArraySize = tlsServerEndPointByteArray.Length;

            bindingsObj = new Bindings();

            IntPtr channelBindingsPtr = Marshal.AllocHGlobal(secChannelBindingSize + tlsServerEndPointByteArraySize + HashMaxLength);

            bindingsObj.pBindings = channelBindingsPtr;

            channelBindingsPtr = channelBindingsPtr + secChannelBindingSize;

            Marshal.Copy(tlsServerEndPointByteArray, 0, channelBindingsPtr, tlsServerEndPointByteArraySize);

            channelBindingsPtr = channelBindingsPtr + tlsServerEndPointByteArraySize;

            SafeX509Handle cert = Interop.OpenSsl.GetPeerCertificate(context);

            bool gotRef = false;

            try
            {
                cert.DangerousAddRef(ref gotRef);

                // TODO directly referring EVP_sha256 in below code is not as per RFC. but I could not find, a good way to 
                // fetch desired data from cert & then get correct function. Need to fix later.
#if false
                Interop.libcrypto.X509_digest(cert, libcrypto.EVP_get_digestbynid(n), channelBindingsPtr, ref certHashSize);
#endif
                Interop.libcrypto.X509_digest(cert, libcrypto.EVP_sha256(), channelBindingsPtr, ref certHashSize);
            }
            finally
            {
                if(gotRef)
                {
                    cert.DangerousRelease();
                }
            }

            SEC_CHANNEL_BINDINGS channelBindings = new SEC_CHANNEL_BINDINGS()
            {
                cbApplicationDataLength = tlsServerEndPointByteArraySize + certHashSize,
                dwApplicationDataOffset = (Int32)secChannelBindingSize
            };

            bindingsObj.length = secChannelBindingSize + channelBindings.cbApplicationDataLength;

            Marshal.StructureToPtr(channelBindings, bindingsObj.pBindings, true);          
        }

        internal static void getUniqueChannelBindings(SafeSslHandle context, ChannelBindingKind attribute, bool isServer, out Bindings bindingsObj)
        {
            int TlsUniqueByteArraySize = TlsUniqueByteArray.Length;

            bindingsObj = new Bindings();

            IntPtr channelBindingsPtr = Marshal.AllocHGlobal(secChannelBindingSize + TlsUniqueByteArraySize + HashMaxLength);

            bindingsObj.pBindings = channelBindingsPtr;

            channelBindingsPtr = channelBindingsPtr + secChannelBindingSize;

            Marshal.Copy(TlsUniqueByteArray, 0, channelBindingsPtr, TlsUniqueByteArraySize);

            channelBindingsPtr = channelBindingsPtr + TlsUniqueByteArraySize;

            bool sessionReused = Interop.libssl.SSL_session_reused(context);

            int certHashSize = isServer ^ sessionReused ? Interop.libssl.SSL_get_peer_finished(context, channelBindingsPtr, HashMaxLength) :
                                                            Interop.libssl.SSL_get_finished(context, channelBindingsPtr, HashMaxLength);

            SEC_CHANNEL_BINDINGS channelBindings = new SEC_CHANNEL_BINDINGS()
            {
                cbApplicationDataLength = TlsUniqueByteArray.Length + certHashSize,
                dwApplicationDataOffset = (Int32)secChannelBindingSize
            };

            bindingsObj.length = secChannelBindingSize + channelBindings.cbApplicationDataLength;

            Marshal.StructureToPtr(channelBindings, bindingsObj.pBindings, true);
        }
    }
}
