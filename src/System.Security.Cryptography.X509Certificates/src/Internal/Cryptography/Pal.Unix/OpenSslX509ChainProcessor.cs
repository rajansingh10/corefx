﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed class OpenSslX509ChainProcessor : IChainPal
    {
        // Constructed (0x20) | Sequence (0x10) => 0x30.
        private const uint ConstructedSequenceTagId = 0x30;

        public void Dispose()
        {
        }

        public bool? Verify(X509VerificationFlags flags, out Exception exception)
        {
            if (flags != X509VerificationFlags.NoFlag)
            {
                // TODO (#2204): Add support for X509VerificationFlags, or throw PlatformNotSupportedException.
                throw new NotSupportedException(SR.WorkInProgress);
            }
            
            exception = null;
            return ChainStatus.Length == 0;
        }

        public X509ChainElement[] ChainElements { get; private set; }
        public X509ChainStatus[] ChainStatus { get; private set; }

        public SafeX509ChainHandle SafeHandle
        {
            get { return null; }
        }

        public static IChainPal BuildChain(
            X509Certificate2 leaf,
            List<X509Certificate2> candidates,
            List<X509Certificate2> downloaded,
            List<X509Certificate2> systemTrusted,
            OidCollection applicationPolicy,
            OidCollection certificatePolicy,
            X509RevocationMode revocationMode,
            X509RevocationFlag revocationFlag,
            DateTime verificationTime,
            ref TimeSpan remainingDownloadTime)
        {
            X509ChainElement[] elements;
            List<X509ChainStatus> overallStatus = new List<X509ChainStatus>();

            // An X509_STORE is more comparable to Cryptography.X509Certificate2Collection than to
            // Cryptography.X509Store. So read this with OpenSSL eyes, not CAPI/CNG eyes.
            //
            // (If you need to think of it as an X509Store, it's a volatile memory store)
            using (SafeX509StoreHandle store = Interop.libcrypto.X509_STORE_new())
            using (SafeX509StoreCtxHandle storeCtx = Interop.libcrypto.X509_STORE_CTX_new())
            {
                Interop.Crypto.CheckValidOpenSslHandle(store);
                Interop.Crypto.CheckValidOpenSslHandle(storeCtx);

                bool lookupCrl = revocationMode != X509RevocationMode.NoCheck;

                foreach (X509Certificate2 cert in candidates)
                {
                    OpenSslX509CertificateReader pal = (OpenSslX509CertificateReader)cert.Pal;

                    if (!Interop.libcrypto.X509_STORE_add_cert(store, pal.SafeHandle))
                    {
                        throw Interop.Crypto.CreateOpenSslCryptographicException();
                    }

                    if (lookupCrl)
                    {
                        CrlCache.AddCrlForCertificate(
                            cert,
                            store,
                            revocationMode,
                            verificationTime,
                            ref remainingDownloadTime);

                        // If we only wanted the end-entity certificate CRL then don't look up
                        // any more of them.
                        lookupCrl = revocationFlag != X509RevocationFlag.EndCertificateOnly;
                    }
                }

                if (revocationMode != X509RevocationMode.NoCheck)
                {
                    Interop.libcrypto.X509VerifyFlags vfyFlags = Interop.libcrypto.X509VerifyFlags.X509_V_FLAG_CRL_CHECK;

                    if (revocationFlag != X509RevocationFlag.EndCertificateOnly)
                    {
                        vfyFlags |= Interop.libcrypto.X509VerifyFlags.X509_V_FLAG_CRL_CHECK_ALL;
                    }

                    if (!Interop.libcrypto.X509_STORE_set_flags(store, vfyFlags))
                    {
                        throw Interop.Crypto.CreateOpenSslCryptographicException();
                    }
                }

                // When CRL checking support is added, it should be done before the call to
                // X509_STORE_CTX_init (aka here) by calling X509_STORE_set_flags(store, flags);

                SafeX509Handle leafHandle = ((OpenSslX509CertificateReader)leaf.Pal).SafeHandle;

                if (!Interop.libcrypto.X509_STORE_CTX_init(storeCtx, store, leafHandle, IntPtr.Zero))
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                Interop.Crypto.SetX509ChainVerifyTime(storeCtx, verificationTime);

                int verify = Interop.libcrypto.X509_verify_cert(storeCtx);

                if (verify < 0)
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                using (SafeX509StackHandle chainStack = Interop.libcrypto.X509_STORE_CTX_get1_chain(storeCtx))
                {
                    int chainSize = Interop.Crypto.GetX509StackFieldCount(chainStack);
                    int errorDepth = -1;
                    Interop.libcrypto.X509VerifyStatusCode errorCode = 0;

                    if (verify == 0)
                    {
                        errorCode = Interop.libcrypto.X509_STORE_CTX_get_error(storeCtx);
                        errorDepth = Interop.libcrypto.X509_STORE_CTX_get_error_depth(storeCtx);
                    }

                    elements = new X509ChainElement[chainSize];
                    int maybeRootDepth = chainSize - 1;

                    // The leaf cert is 0, up to (maybe) the root at chainSize - 1
                    for (int i = 0; i < chainSize; i++)
                    {
                        List<X509ChainStatus> status = new List<X509ChainStatus>();

                        if (i == errorDepth)
                        {
                            AddElementStatus(errorCode, status, overallStatus);
                        }

                        IntPtr elementCertPtr = Interop.Crypto.GetX509StackField(chainStack, i);

                        if (elementCertPtr == IntPtr.Zero)
                        {
                            throw Interop.Crypto.CreateOpenSslCryptographicException();
                        }

                        // Duplicate the certificate handle
                        X509Certificate2 elementCert = new X509Certificate2(elementCertPtr);

                        // If the last cert is self signed then it's the root cert, do any extra checks.
                        if (i == maybeRootDepth && IsSelfSigned(elementCert))
                        {
                            // If the root certificate was downloaded or the system
                            // doesn't trust it, it's untrusted.
                            if (downloaded.Contains(elementCert) ||
                                !systemTrusted.Contains(elementCert))
                            {
                                AddElementStatus(
                                    Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_UNTRUSTED,
                                    status,
                                    overallStatus);
                            }
                        }

                        elements[i] = new X509ChainElement(elementCert, status.ToArray(), "");
                    }
                }
            }

            if ((certificatePolicy != null && certificatePolicy.Count > 0) ||
                (applicationPolicy != null && applicationPolicy.Count > 0))
            {
                List<X509Certificate2> certsToRead = new List<X509Certificate2>();

                foreach (X509ChainElement element in elements)
                {
                    certsToRead.Add(element.Certificate);
                }

                CertificatePolicyChain policyChain = new CertificatePolicyChain(certsToRead);

                bool failsPolicyChecks = false;

                if (certificatePolicy != null)
                {
                    if (!policyChain.MatchesCertificatePolicies(certificatePolicy))
                    {
                        failsPolicyChecks = true;
                    }
                }

                if (applicationPolicy != null)
                {
                    if (!policyChain.MatchesApplicationPolicies(applicationPolicy))
                    {
                        failsPolicyChecks = true;
                    }
                }

                if (failsPolicyChecks)
                {
                    X509ChainElement leafElement = elements[0];

                    X509ChainStatus chainStatus = new X509ChainStatus
                    {
                        Status = X509ChainStatusFlags.InvalidPolicyConstraints,
                        StatusInformation = SR.Chain_NoPolicyMatch,
                    };

                    var elementStatus = new List<X509ChainStatus>(leafElement.ChainElementStatus.Length + 1);
                    elementStatus.AddRange(leafElement.ChainElementStatus);

                    AddUniqueStatus(elementStatus, ref chainStatus);
                    AddUniqueStatus(overallStatus, ref chainStatus);

                    elements[0] = new X509ChainElement(
                        leafElement.Certificate,
                        elementStatus.ToArray(),
                        leafElement.Information);
                }
            }

            return new OpenSslX509ChainProcessor
            {
                ChainStatus = overallStatus.ToArray(),
                ChainElements = elements,
            };
        }

        private static void AddElementStatus(
            Interop.libcrypto.X509VerifyStatusCode errorCode,
            List<X509ChainStatus> elementStatus,
            List<X509ChainStatus> overallStatus)
        {
            X509ChainStatusFlags statusFlag = MapVerifyErrorToChainStatus(errorCode);

            Debug.Assert(
                (statusFlag & (statusFlag - 1)) == 0,
                "Status flag has more than one bit set",
                "More than one bit is set in status '{0}' for error code '{1}'",
                statusFlag,
                errorCode);

            foreach (X509ChainStatus currentStatus in elementStatus)
            {
                if ((currentStatus.Status & statusFlag) != 0)
                {
                    return;
                }
            }

            X509ChainStatus chainStatus = new X509ChainStatus
            {
                Status = MapVerifyErrorToChainStatus(errorCode),
                StatusInformation = Interop.libcrypto.X509_verify_cert_error_string(errorCode),
            };

            elementStatus.Add(chainStatus);
            AddUniqueStatus(overallStatus, ref chainStatus);
        }
        
        private static void AddUniqueStatus(IList<X509ChainStatus> list, ref X509ChainStatus status)
        {
            X509ChainStatusFlags statusCode = status.Status;

            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].Status == statusCode)
                {
                    return;
                }
            }

            list.Add(status);
        }

        private static X509ChainStatusFlags MapVerifyErrorToChainStatus(Interop.libcrypto.X509VerifyStatusCode code)
        {
            switch (code)
            {
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_OK:
                    return X509ChainStatusFlags.NoError;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_NOT_YET_VALID:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_HAS_EXPIRED:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
                    return X509ChainStatusFlags.NotTimeValid;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_REVOKED:
                    return X509ChainStatusFlags.Revoked;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_SIGNATURE_FAILURE:
                    return X509ChainStatusFlags.NotSignatureValid;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_UNTRUSTED:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                    return X509ChainStatusFlags.UntrustedRoot;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CRL_HAS_EXPIRED:
                    return X509ChainStatusFlags.OfflineRevocation;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CRL_NOT_YET_VALID:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CRL_SIGNATURE_FAILURE:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_GET_CRL:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
                    return X509ChainStatusFlags.RevocationStatusUnknown;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_INVALID_EXTENSION:
                    return X509ChainStatusFlags.InvalidExtension;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                    return X509ChainStatusFlags.PartialChain;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_INVALID_PURPOSE:
                    return X509ChainStatusFlags.NotValidForUsage;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_INVALID_CA:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_INVALID_NON_CA:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_PATH_LENGTH_EXCEEDED:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
                    return X509ChainStatusFlags.InvalidBasicConstraints;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_INVALID_POLICY_EXTENSION:
                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_NO_EXPLICIT_POLICY:
                    return X509ChainStatusFlags.InvalidPolicyConstraints;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_REJECTED:
                    return X509ChainStatusFlags.ExplicitDistrust;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                    return X509ChainStatusFlags.HasNotSupportedCriticalExtension;

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_CERT_CHAIN_TOO_LONG:
                    throw new CryptographicException();

                case Interop.libcrypto.X509VerifyStatusCode.X509_V_ERR_OUT_OF_MEM:
                    throw new OutOfMemoryException();

                default:
                    Debug.Fail("Unrecognized X509VerifyStatusCode:" + code);
                    throw new CryptographicException();
            }
        }

        internal static List<X509Certificate2> FindCandidates(
            X509Certificate2 leaf,
            X509Certificate2Collection extraStore,
            List<X509Certificate2> downloaded,
            List<X509Certificate2> systemTrusted,
            ref TimeSpan remainingDownloadTime)
        {
            List<X509Certificate2> candidates = new List<X509Certificate2>();
            Queue<X509Certificate2> toProcess = new Queue<X509Certificate2>();
            toProcess.Enqueue(leaf);

            using (var systemRootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
            using (var systemIntermediateStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine))
            using (var userRootStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            using (var userIntermediateStore = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser))
            {
                systemRootStore.Open(OpenFlags.ReadOnly);
                systemIntermediateStore.Open(OpenFlags.ReadOnly);
                userRootStore.Open(OpenFlags.ReadOnly);
                userIntermediateStore.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection systemRootCerts = systemRootStore.Certificates;
                X509Certificate2Collection systemIntermediateCerts = systemIntermediateStore.Certificates;
                X509Certificate2Collection userRootCerts = userRootStore.Certificates;
                X509Certificate2Collection userIntermediateCerts = userIntermediateStore.Certificates;

                // fill the system trusted collection
                foreach (X509Certificate2 systemRootCert in systemRootCerts)
                {
                    systemTrusted.Add(systemRootCert);
                }
                foreach (X509Certificate2 userRootCert in userRootCerts)
                {
                    systemTrusted.Add(userRootCert);
                }

                X509Certificate2Collection[] storesToCheck =
                {
                    extraStore,
                    userIntermediateCerts,
                    systemIntermediateCerts,
                    userRootCerts,
                    systemRootCerts,
                };

                while (toProcess.Count > 0)
                {
                    X509Certificate2 current = toProcess.Dequeue();

                    if (!candidates.Contains(current))
                    {
                        candidates.Add(current);
                    }

                    List<X509Certificate2> results = FindIssuer(
                        current,
                        storesToCheck,
                        downloaded,
                        ref remainingDownloadTime);

                    if (results != null)
                    {
                        foreach (X509Certificate2 result in results)
                        {
                            if (!candidates.Contains(result))
                            {
                                toProcess.Enqueue(result);
                            }
                        }
                    }
                }
            }

            return candidates;
        }

        private static List<X509Certificate2> FindIssuer(
            X509Certificate2 cert,
            X509Certificate2Collection[] stores,
            List<X509Certificate2> downloadedCerts,
            ref TimeSpan remainingDownloadTime)
        {
            if (IsSelfSigned(cert))
            {
                // It's a root cert, we won't make any progress.
                return null;
            }

            SafeX509Handle certHandle = ((OpenSslX509CertificateReader)cert.Pal).SafeHandle;

            foreach (X509Certificate2Collection store in stores)
            {
                List<X509Certificate2> fromStore = null;

                foreach (X509Certificate2 candidate in store)
                {
                    SafeX509Handle candidateHandle = ((OpenSslX509CertificateReader)candidate.Pal).SafeHandle;

                    int issuerError = Interop.libcrypto.X509_check_issued(candidateHandle, certHandle);

                    if (issuerError == 0)
                    {
                        if (fromStore == null)
                        {
                            fromStore = new List<X509Certificate2>();
                        }

                        if (!fromStore.Contains(candidate))
                        {
                            fromStore.Add(candidate);
                        }
                    }
                }

                if (fromStore != null)
                {
                    return fromStore;
                }
            }

            byte[] authorityInformationAccess = null;

            foreach (X509Extension extension in cert.Extensions)
            {
                if (StringComparer.Ordinal.Equals(extension.Oid.Value, Oids.AuthorityInformationAccess))
                {
                    // If there's an Authority Information Access extension, it might be used for
                    // looking up additional certificates for the chain.
                    authorityInformationAccess = extension.RawData;
                    break;
                }
            }

            if (authorityInformationAccess != null)
            {
                X509Certificate2 downloaded = DownloadCertificate(
                    authorityInformationAccess,
                    ref remainingDownloadTime);

                if (downloaded != null)
                {
                    downloadedCerts.Add(downloaded);

                    return new List<X509Certificate2>(1) { downloaded };
                }
            }

            return null;
        }

        private static bool IsSelfSigned(X509Certificate2 cert)
        {
            return StringComparer.Ordinal.Equals(cert.Subject, cert.Issuer);
        }

        private static X509Certificate2 DownloadCertificate(
            byte[] authorityInformationAccess,
            ref TimeSpan remainingDownloadTime)
        {
            // Don't do any work if we're over limit.
            if (remainingDownloadTime <= TimeSpan.Zero)
            {
                return null;
            }

            string uri = FindHttpAiaRecord(authorityInformationAccess, Oids.CertificateAuthorityIssuers);

            if (uri == null)
            {
                return null;
            }

            return CertificateAssetDownloader.DownloadCertificate(uri, ref remainingDownloadTime);
        }

        internal static string FindHttpAiaRecord(byte[] authorityInformationAccess, string recordTypeOid)
        {
            DerSequenceReader reader = new DerSequenceReader(authorityInformationAccess);

            while (reader.HasData)
            {
                DerSequenceReader innerReader = reader.ReadSequence();

                // If the sequence's first element is a sequence, unwrap it.
                if (innerReader.PeekTag() == ConstructedSequenceTagId)
                {
                    innerReader = innerReader.ReadSequence();
                }

                Oid oid = innerReader.ReadOid();

                if (StringComparer.Ordinal.Equals(oid.Value, recordTypeOid))
                {
                    string uri = innerReader.ReadIA5String();

                    Uri parsedUri;
                    if (!Uri.TryCreate(uri, UriKind.Absolute, out parsedUri))
                    {
                        continue;
                    }

                    if (!StringComparer.Ordinal.Equals(parsedUri.Scheme, "http"))
                    {
                        continue;
                    }

                    return uri;
                }
            }

            return null;
        }
    }
}
