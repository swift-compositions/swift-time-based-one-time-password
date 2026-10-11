import Dependencies
import Foundation
import OneTimePasswordShared

public typealias TOTP = RFC_6238.TOTP

extension TOTP {
    public typealias Algorithm = RFC_6238.Algorithm
    public typealias Error = RFC_6238.Error
}

extension TOTP {

    public var currentOTP: String {
        get throws(RFC_6238.Error) {
            try generate()
        }
    }

    public var base32Secret: String {
        RFC_6238.Base32.encode(secret)
    }

    public func generate() throws(RFC_6238.Error) -> String {
        @Dependency(\.date) var date
        return try generate(at: date())
    }

    public func generate(at time: Date) throws(RFC_6238.Error) -> String {
        try generate(at: time.timeIntervalSince1970, using: CryptoHMACProvider())
    }

    public func validate(_ otp: String, window: Int = 1) throws(RFC_6238.Error) -> Bool {
        @Dependency(\.date) var date
        return try validate(otp, at: date(), window: window)
    }

    public func validate(_ otp: String, at time: Date, window: Int = 1) throws(RFC_6238.Error) -> Bool {
        try validate(otp, at: time.timeIntervalSince1970, window: window, using: CryptoHMACProvider())
    }

    public func timeRemaining() -> TimeInterval {
        @Dependency(\.date) var date
        return timeRemaining(at: date().timeIntervalSince1970)
    }

    public func timeRemaining(at time: Date) -> TimeInterval {
        timeRemaining(at: time.timeIntervalSince1970)
    }

    public func generateSequence(count: Int = 2) throws(RFC_6238.Error) -> [(otp: String, timeRemaining: TimeInterval)] {
        @Dependency(\.date) var date
        let now = date()
        var results: [(String, TimeInterval)] = []

        for i in 0..<count {
            let time = Date(timeIntervalSince1970: now.timeIntervalSince1970 + Double(i) * timeStep)
            let otp = try generate(at: time)
            let remaining = timeRemaining(at: time.timeIntervalSince1970)
            results.append((otp, remaining))
        }

        return results
    }
}
