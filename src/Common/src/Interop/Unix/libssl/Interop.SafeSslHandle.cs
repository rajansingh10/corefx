// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
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
            private readonly SafeBioHandle _readBio;
            private readonly SafeBioHandle _writeBio;
            private bool _isServer;

            public bool IsServer
            {
                get {return _isServer;}
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

            public SafeSslHandle(SafeSslContextHandle context, bool isServer)
                : base(IntPtr.Zero, true)
            {
                _isServer = isServer;

                IntPtr memMethod = Interop.libcrypto.BIO_s_mem();
                _readBio = Interop.libcrypto.BIO_new(memMethod);
                _writeBio = Interop.libcrypto.BIO_new(memMethod);
                
                IntPtr tempHandle = SSL_new(context);
                if (tempHandle == IntPtr.Zero)
                {
                    return;
                }

                // After SSL_set_bio, the BIO handles are owned by SSL pointer
                // and are automatically freed by SSL_free. To prevent a double
                // free, we need to keep the ref counts bumped up till SSL_free
                bool gotReadRef = false, gotWriteRef = false;
                _readBio.DangerousAddRef(ref gotReadRef);
                _writeBio.DangerousAddRef(ref gotWriteRef);
                SSL_set_bio(tempHandle, _readBio.DangerousGetHandle(), _writeBio.DangerousGetHandle());
                handle = tempHandle;

                if (isServer)
                {
                    SSL_set_accept_state(handle);
                }
                else
                {
                    SSL_set_connect_state(handle);
                }
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                SSL_free(handle);
                _readBio.SetHandleAsInvalid();  // BIO got freed in SSL_free
                _writeBio.SetHandleAsInvalid();  // BIO got freed in SSL_free
                return true;
            }
        }
    }
}
