<?php

namespace EbicsApi\Ebics\Services;

use EbicsApi\Ebics\Contracts\SignatureInterface;

/**
 * Ebics 3.0 DigestResolver.
 *
 * Patched: fallback to public key digest when no certificate is available.
 * Some banks (e.g. PostFinance) use EBICS 3.0 with keys instead of certificates.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class DigestResolverV3 extends DigestResolver
{
    public function signDigest(SignatureInterface $signature, string $algorithm = 'sha256'): string
    {
        if (($certificateContent = $signature->getCertificateContent())) {
            return $this->cryptService->calculateCertificateFingerprint(
                $certificateContent,
                $algorithm
            );
        }
        // Fallback to public key digest when no certificate is available
        return $this->cryptService->calculatePublicKeyDigest($signature, $algorithm);
    }

    public function confirmDigest(SignatureInterface $signature, string $algorithm = 'sha256'): string
    {
        if (($certificateContent = $signature->getCertificateContent())) {
            $digest = $this->cryptService->calculateCertificateFingerprint($certificateContent, $algorithm);
        } else {
            $digest = $this->cryptService->calculatePublicKeyDigest($signature, $algorithm);
        }

        return bin2hex($digest);
    }
}
