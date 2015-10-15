// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class libssl
    {
        internal sealed class SafeSslContextHandle : SafeHandle
        {
            public SafeSslContextHandle(IntPtr method)
                : base(IntPtr.Zero, true)
            {
                handle = SSL_CTX_new(method);
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                SSL_CTX_free(handle);
                return true;
            }
        }

        internal sealed class SafeSslHandle : SafeHandle
        {
            private SafeBioHandle _readBio;
            private SafeBioHandle _writeBio;
            private bool _isServer;

            public bool IsServer
            {
                get { return _isServer; }
            }

            public SafeBioHandle InputBio
            {
                get
                {
                    return _readBio;
                }
            }

            public SafeBioHandle OutputBio
            {
                get
                {
                    return _writeBio;
                }
            }

            public static SafeSslHandle Create(SafeSslContextHandle context, bool isServer)
            {
                SafeBioHandle readBio = Crypto.CreateMemoryBio();
                if (readBio.IsInvalid)
                {
                    return new SafeSslHandle();
                }

                SafeBioHandle writeBio = Crypto.CreateMemoryBio();
                if (writeBio.IsInvalid)
                {
                    readBio.Dispose();
                    return new SafeSslHandle();
                }
                
                SafeSslHandle handle = SSL_new(context);
                if (handle.IsInvalid)
                {
                    readBio.Dispose();
                    writeBio.Dispose();
                    return handle;
                }
                handle._isServer = isServer;

                // After SSL_set_bio, the BIO handles are owned by SSL pointer
                // and are automatically freed by SSL_free. To prevent a double
                // free, we need to keep the ref counts bumped up till SSL_free
                bool gotRef = false;
                readBio.DangerousAddRef(ref gotRef);
                try
                {
                    bool ignore = false;
                    writeBio.DangerousAddRef(ref ignore);
                }
                catch
                {
                    if (gotRef)
                    {
                        readBio.DangerousRelease();
                    }
                    throw;
                }

                SSL_set_bio(handle, readBio, writeBio);
                handle._readBio = readBio;
                handle._writeBio = writeBio;

                if (isServer)
                {
                    SSL_set_accept_state(handle);
                }
                else
                {
                    SSL_set_connect_state(handle);
                }
                return handle;
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                SSL_free(handle);
                if (_readBio != null)
                {
                    _readBio.SetHandleAsInvalid(); // BIO got freed in SSL_free
                }
                if (_writeBio != null)
                {
                    _writeBio.SetHandleAsInvalid(); // BIO got freed in SSL_free
                }
                return true;
            }

            private SafeSslHandle() : base(IntPtr.Zero, true)
            {
            }   
        }

        internal sealed class SafeChannelBinding : SafeHandle
        {
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

            private static readonly byte[] s_tlsServerEndPointByteArray = Encoding.UTF8.GetBytes("tls-server-end-point:");
            private static readonly byte[] s_tlsUniqueByteArray = Encoding.UTF8.GetBytes("tls-unique:");
            private static readonly int secChannelBindingSize = Marshal.SizeOf<SEC_CHANNEL_BINDINGS>();
            private readonly int cbtPrefixByteArraySize;
            private const int CertHashMaxSize = 128;

            internal int Length
            {
                get;
                private set;
            }

            internal IntPtr CertHashPtr
            {
                get;
                private set;
            }

            private byte[] GetPrefixBytes(ChannelBindingKind kind)
            {
                if (kind == ChannelBindingKind.Endpoint)
                {
                    return s_tlsServerEndPointByteArray;
                }
                else
                {
                    return s_tlsUniqueByteArray;
                }
            }

            internal SafeChannelBinding(ChannelBindingKind kind)
                : base(IntPtr.Zero, true)
            {
                byte[] cbtPrefix = GetPrefixBytes(kind);
                cbtPrefixByteArraySize = cbtPrefix.Length;
                handle = Marshal.AllocHGlobal(secChannelBindingSize + cbtPrefixByteArraySize + CertHashMaxSize);
                IntPtr cbtPrefixPtr = handle + secChannelBindingSize;
                Marshal.Copy(cbtPrefix, 0, cbtPrefixPtr, cbtPrefixByteArraySize);
                CertHashPtr = cbtPrefixPtr + cbtPrefixByteArraySize;
                Length = CertHashMaxSize;
            }

            internal void SetCertHashLength(int certHashLength)
            {
                int cbtLength = cbtPrefixByteArraySize + certHashLength;
                Length = secChannelBindingSize + cbtLength;

                SEC_CHANNEL_BINDINGS channelBindings = new SEC_CHANNEL_BINDINGS()
                {
                    cbApplicationDataLength = cbtLength,
                    dwApplicationDataOffset = (Int32)secChannelBindingSize
                };
                Marshal.StructureToPtr(channelBindings, handle, true);
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }
    }
}
