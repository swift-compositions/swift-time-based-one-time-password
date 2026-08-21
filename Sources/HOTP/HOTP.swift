import Foundation
import OneTimePasswordShared

public typealias HOTP = RFC_6238.HOTP

extension HOTP {
    public typealias Algorithm = RFC_6238.Algorithm
    public typealias Error = RFC_6238.Error
}

extension HOTP {

    public init(
        base32Secret: String,
        digits: Int = 6,
        algorithm: RFC_6238.Algorithm = .sha1
    ) throws(RFC_6238.Error) {
        guard let secret = RFC_6238.Base32.decode(base32Secret) else {
            throw RFC_6238.Error.invalidBase32String
        }
        try self.init(secret: secret, digits: digits, algorithm: algorithm)
    }

    public func validate(_ otp: String, counter: UInt64) -> Bool {
        let expected = generate(counter: counter, using: CryptoHMACProvider())
        return constantTimeCompare(otp, expected)
    }
}

private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
    guard a.count == b.count else { return false }

    var result = 0
    for (charA, charB) in zip(a, b) {
        result |= Int(charA.asciiValue ?? 0) ^ Int(charB.asciiValue ?? 0)
    }

    return result == 0
}
