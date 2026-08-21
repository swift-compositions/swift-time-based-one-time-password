import Foundation
import OneTimePasswordShared

extension TOTP {

    public struct MigrationParameters {
        public let secret: String
        public let issuer: String
        public let accountName: String
        public let algorithm: RFC_6238.Algorithm
        public let digits: Int
        public let period: Int

        public init(
            secret: String,
            issuer: String,
            accountName: String,
            algorithm: RFC_6238.Algorithm = .sha1,
            digits: Int = 6,
            period: Int = 30
        ) {
            self.secret = secret
            self.issuer = issuer
            self.accountName = accountName
            self.algorithm = algorithm
            self.digits = digits
            self.period = period
        }
    }

    public static func from(migration params: MigrationParameters) throws(RFC_6238.Error) -> TOTP {
        try TOTP(
            base32Secret: params.secret,
            timeStep: TimeInterval(params.period),
            digits: params.digits,
            algorithm: params.algorithm
        )
    }

    public func exportMigration(issuer: String, accountName: String) -> MigrationParameters {
        MigrationParameters(
            secret: RFC_6238.Base32.encode(secret),
            issuer: issuer,
            accountName: accountName,
            algorithm: algorithm,
            digits: digits,
            period: Int(timeStep)
        )
    }
}
