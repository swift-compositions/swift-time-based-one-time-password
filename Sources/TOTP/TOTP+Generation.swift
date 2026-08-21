import Crypto
import Foundation
import OneTimePasswordShared

extension TOTP {

    public static func sha1(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP {
        try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha1)
    }

    public static func sha256(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP
    {
        try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha256)
    }

    public static func sha512(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP
    {
        try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha512)
    }

    public static func generateSecret(length: Int = 20) -> String {
        let key = SymmetricKey(size: .init(bitCount: length * 8))
        let bytes = key.withUnsafeBytes { Array($0) }
        return RFC_6238.Base32.encode(bytes)
    }

    public static func generateNew(
        algorithm: RFC_6238.Algorithm = .sha1,
        digits: Int = 6,
        timeStep: TimeInterval = 30
    ) throws(RFC_6238.Error) -> TOTP {

        let keyLength: Int
        switch algorithm {
        case .sha1:
            keyLength = 20

        case .sha256:
            keyLength = 32

        case .sha512:
            keyLength = 64
        }

        let key = SymmetricKey(size: .init(bitCount: keyLength * 8))
        let keyData = key.withUnsafeBytes { Array($0) }

        return try TOTP(
            secret: keyData,
            timeStep: timeStep,
            digits: digits,
            algorithm: algorithm
        )
    }

    public init(
        symmetricKey: SymmetricKey,
        algorithm: RFC_6238.Algorithm = .sha1,
        digits: Int = 6,
        timeStep: TimeInterval = 30
    ) throws(RFC_6238.Error) {
        let keyData = symmetricKey.withUnsafeBytes { Array($0) }
        try self.init(
            secret: keyData,
            timeStep: timeStep,
            digits: digits,
            algorithm: algorithm
        )
    }
}
